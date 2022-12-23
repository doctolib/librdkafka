/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2017 Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Builtin SASL AWS MSK IAM support
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <curl/curl.h>
#include <sys/time.h>

#include "rdkafka_int.h"
#include "rdkafka_transport.h"
#include "rdkafka_transport_int.h"
#include "rdkafka_sasl.h"
#include "rdkafka_sasl_int.h"

#include "rdstringbuilder.h"
#include "rdtypes.h"
#include "rdunittest.h"

#if WITH_SSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "rdkafka_aws.h"
#else
#error "WITH_SSL (OpenSSL) is required for SASL AWS MSK IAM"
#endif

#define AWS_REFRESH_NO_REFRESH 0
#define AWS_REFRESH_METADATA 1
#define AWS_REFRESH_WEB_IDENTITY_TOKEN_FILE 2

/**
 * @struct Per-client-instance SASL/AWS_MSK_IAM handle.
 */
typedef struct rd_kafka_sasl_aws_msk_iam_handle_s {
        /**< Read-write lock for fields in the handle. */
        rwlock_t lock;

        /**< Required AWS credential values. */
        char *aws_access_key_id;  /* AWS access key id from conf */
        char *aws_secret_access_key;  /* AWS secret access key from conf */
        char *aws_region;  /* AWS region from conf */
        char *aws_security_token;  /* AWS security token from conf (optional) */

        /**< When the credentials expire, in terms of the number of
         *   milliseconds since the epoch. Wall clock time.
         */
        rd_ts_t wts_md_lifetime;

        /**< The point after which credentials should be replaced with
         * new ones, in terms of the number of milliseconds since the
         * epoch. Wall clock time.
         */
        rd_ts_t wts_refresh_after;

        /**< When the last credential refresh was enqueued (0 = never)
         *   in terms of the number of milliseconds since the epoch.
         *   Wall clock time.
         */
        rd_ts_t wts_enqueued_refresh;

        /**< Error message for validation and/or credential retrieval problems. */
        char *errstr;

        /**< Back-pointer to client instance. */
        rd_kafka_t *rk;

        /**< Credential refresh timer */
        rd_kafka_timer_t credential_refresh_tmr;

} rd_kafka_sasl_aws_msk_iam_handle_t;

/**
 * @brief Per-connection state
 */
struct rd_kafka_sasl_aws_msk_iam_state {
        enum {
            RD_KAFKA_SASL_AWS_MSK_IAM_SEND_CLIENT_FIRST_MESSAGE,
            RD_KAFKA_SASL_AWS_MSK_IAM_RECEIVE_SERVER_RESPONSE,
        } state;
        const EVP_MD *md;  /* hash function pointer */
        char *hostname;  /* hostname from client_new */

        /*
         * A place to store a consistent view of the token and extensions
         * throughout the authentication process -- even if it is refreshed
         * midway through this particular authentication.
         */
        char *aws_access_key_id;  /* AWS access key id from conf */
        char *aws_secret_access_key;  /* AWS secret access key from conf */
        char *aws_region;  /* AWS region from conf */
        char *aws_security_token;  /* AWS security token from conf (optional) */
};

/**
 * @brief free memory inside the given credential
 */
static void rd_kafka_sasl_aws_msk_iam_credential_free (
        rd_kafka_aws_credential_t *credential) {
        RD_IF_FREE(credential->aws_access_key_id, rd_free);
        RD_IF_FREE(credential->aws_secret_access_key, rd_free);
        RD_IF_FREE(credential->aws_security_token, rd_free);

        memset(credential, 0, sizeof(*credential));
}

/**
 * @brief Set SASL/AWS_MSK_IAM token and metadata
 *
 * @param rk Client instance.
 * @param credential AWS Credentials
 * @param aws_region AWS Region
 * @param md_lifetime_ms when the credential expires, in terms of the number of
 *  milliseconds since the epoch. See https://currentmillis.com/.
 *
 * @returns \c RD_KAFKA_RESP_ERR_NO_ERROR on success, otherwise errstr set and:
 *          \c RD_KAFKA_RESP_ERR__INVALID_ARG if any of the arguments are
 *              invalid;
 *          \c RD_KAFKA_RESP_ERR__STATE if SASL/OAUTHBEARER is not configured as
 *              the client's authentication mechanism.
 *
 * @sa rd_kafka_aws_msk_iam_set_credential_failure
 */
static rd_kafka_resp_err_t
rd_kafka_aws_msk_iam_set_credential (rd_kafka_t *rk,
        rd_kafka_aws_credential_t * credential,
        const char * aws_region,
        char *errstr, size_t errstr_size) {
        rd_kafka_sasl_aws_msk_iam_handle_t *handle = rk->rk_sasl.handle;
        rd_ts_t now_wallclock;
        rd_ts_t wts_md_lifetime = credential->md_lifetime_ms * 1000;

        /* Check if SASL/AWS_MSK_IAM is the configured auth mechanism */
        if (rk->rk_conf.sasl.provider != &rd_kafka_sasl_aws_msk_iam_provider ||
            !handle) {
                rd_snprintf(errstr, errstr_size, "SASL/AWS_MSK_IAM is not the "
                            "configured authentication mechanism");
                return RD_KAFKA_RESP_ERR__STATE;
        }

        /* Check args for correct format/value */
        now_wallclock = rd_uclock();
        if (wts_md_lifetime <= now_wallclock) {
                rd_snprintf(errstr, errstr_size,
                            "Must supply an unexpired token: "
                            "now=%"PRId64"ms, exp=%"PRId64"ms",
                            now_wallclock/1000, wts_md_lifetime/1000);
                return RD_KAFKA_RESP_ERR__INVALID_ARG;
        }

        rwlock_wrlock(&handle->lock);

        RD_IF_FREE(handle->aws_access_key_id, rd_free);
        handle->aws_access_key_id = rd_strdup(credential->aws_access_key_id);

        RD_IF_FREE(handle->aws_secret_access_key, rd_free);
        handle->aws_secret_access_key = rd_strdup(credential->aws_secret_access_key);

        RD_IF_FREE(handle->aws_region, rd_free);
        handle->aws_region = rd_strdup(aws_region);

        RD_IF_FREE(handle->aws_security_token, rd_free);
        handle->aws_security_token = rd_strdup(credential->aws_security_token);

        handle->wts_md_lifetime = wts_md_lifetime;

        /* Schedule a refresh 80% through its remaining lifetime */
        handle->wts_refresh_after =
                (rd_ts_t)(now_wallclock + 0.8 *
                        (wts_md_lifetime - now_wallclock));
        rd_kafka_dbg(rk, SECURITY, "BRKMAIN",
                     "Next AWS credential refresh planned %lld\n", handle->wts_refresh_after);

        RD_IF_FREE(handle->errstr, rd_free);
        handle->errstr = NULL;

        rwlock_wrunlock(&handle->lock);

        rd_kafka_dbg(rk, SECURITY, "BRKMAIN",
                     "Waking up waiting broker threads after "
                     "setting AWS_MSK_IAM credential");
        rd_kafka_all_brokers_wakeup(rk, RD_KAFKA_BROKER_STATE_INIT, "AWS IAM Creds reloaded");

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}

/**
 * @brief SASL/AWS_MSK_IAM credential refresh failure indicator.
 *
 * @param rk Client instance.
 * @param errstr mandatory human readable error reason for failing to acquire
 *  a credential.
 *
 * @returns \c RD_KAFKA_RESP_ERR_NO_ERROR on success, otherwise
 *          \c RD_KAFKA_RESP_ERR__STATE if SASL/AWS_MSK_IAM is enabled but is
 *              not configured to be the client's authentication mechanism,
 *          \c RD_KAFKA_RESP_ERR__INVALID_ARG if no error string is supplied.
 * @sa rd_kafka_aws_msk_iam_set_credential
 */
static rd_kafka_resp_err_t
rd_kafka_aws_msk_iam_set_credential_failure (rd_kafka_t *rk, const char *errstr) {
        rd_kafka_sasl_aws_msk_iam_handle_t *handle = rk->rk_sasl.handle;
        rd_bool_t error_changed;

        /* Check if SASL/AWS_MSK_IAM is the configured auth mechanism */
        if (rk->rk_conf.sasl.provider != &rd_kafka_sasl_aws_msk_iam_provider ||
            !handle) {
                return RD_KAFKA_RESP_ERR__STATE;
        }

        if (!errstr || !*errstr) {
                return RD_KAFKA_RESP_ERR__INVALID_ARG;
        }

        rwlock_wrlock(&handle->lock);
        error_changed = !handle->errstr ||
                strcmp(handle->errstr, errstr);
        RD_IF_FREE(handle->errstr, rd_free);
        handle->errstr = rd_strdup(errstr);
        /* Leave any existing credential because it may have some life left,
         * schedule a refresh for 10 seconds later. */
        handle->wts_refresh_after = rd_uclock() + (10*1000*1000);
        rwlock_wrunlock(&handle->lock);

        /* Trigger an ERR__AUTHENTICATION error if the error changed. */
        if (error_changed) {
                rd_kafka_op_err(rk, RD_KAFKA_RESP_ERR__AUTHENTICATION,
                                "Failed to acquire SASL AWS_MSK_IAM credential: %s",
                                errstr);
        }

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}

/**
 * @brief SASL/AWS_MSK_IAM credential refresh using AWS Metadata API.
 */
static int rd_kafka_aws_refresh_with_metadata(
                rd_kafka_t *rk,
                char *errstr, size_t errstr_size) {
        rd_kafka_aws_credential_t credential = RD_ZERO_INIT;
        if (rd_kafka_aws_credentials_from_metadata(&credential, errstr, errstr_size) == -1
                || rd_kafka_aws_msk_iam_set_credential(rk, &credential, rk->rk_conf.sasl.aws_region, errstr, errstr_size) == -1) {
                rd_kafka_sasl_aws_msk_iam_credential_free(&credential);
                rd_kafka_aws_msk_iam_set_credential_failure(rk, errstr);
                return -1;
        }
        rd_kafka_sasl_aws_msk_iam_credential_free(&credential);
        return 0;
}

/**
 * @brief SASL/AWS_MSK_IAM credential refresh using AWS Web identity token file.
 */
static int rd_kafka_aws_refresh_with_web_identity_token_file(
                rd_kafka_t *rk,
                char *errstr, size_t errstr_size) {
        rd_kafka_aws_credential_t credential = RD_ZERO_INIT;

        if (rd_kafka_aws_credentials_with_web_identity_token_file(&credential, rk->rk_conf.sasl.aws_web_identity_token_file, rk->rk_conf.sasl.aws_role_arn,
                  rk->rk_conf.sasl.aws_role_session_name, rk->rk_conf.sasl.aws_duration_sec, errstr, errstr_size) == -1
                || rd_kafka_aws_msk_iam_set_credential(rk, &credential, rk->rk_conf.sasl.aws_region, errstr, errstr_size) == -1) {
                rd_kafka_sasl_aws_msk_iam_credential_free(&credential);
                rd_kafka_aws_msk_iam_set_credential_failure(rk, errstr);
                return -1;
        }
        rd_kafka_sasl_aws_msk_iam_credential_free(&credential);
        return 0;
}

/**
 * @brief SASL/AWS_MSK_IAM credential refresher used for retrieving new temporary
 * credentials from AWS STS service. The refresher will make use of the regional STS
 * endpoints as per https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html.
 *
 * If STS is not used and permanent credentials are provided, the refresher essentially performs a NOOP
 * and will not update the AWS credential information.
 */
static void
rd_kafka_aws_msk_iam_credential_refresh (rd_kafka_t *rk, void *opaque) {
        char errstr[512];

        rd_kafka_dbg(rk, SECURITY, "SASLAWSMSKIAM", "Refreshing AWS credentials");
        if (rk->rk_conf.sasl.aws_refresh_kind == AWS_REFRESH_METADATA) {
                rd_kafka_dbg(rk, SECURITY, "SASLAWSMSKIAM", "Refresh AWS creds from metadata API");
                if (rd_kafka_aws_refresh_with_metadata(rk, errstr, sizeof(errstr)) == -1) {
                        rd_kafka_aws_msk_iam_set_credential_failure(rk, errstr);
                }
        } else if (rk->rk_conf.sasl.aws_refresh_kind == AWS_REFRESH_WEB_IDENTITY_TOKEN_FILE) {
                rd_kafka_dbg(rk, SECURITY, "SASLAWSMSKIAM", "Refresh AWS creds with web identity token file");
                if (rd_kafka_aws_refresh_with_web_identity_token_file(rk, errstr, sizeof(errstr)) == -1) {
                        rd_kafka_aws_msk_iam_set_credential_failure(rk, errstr);
                }
        } else {
                rd_kafka_dbg(rk, SECURITY, "SASLAWSMSKIAM", "No refresh needed");
        }
}

/**
 * @brief Op callback for RD_KAFKA_OP_AWS_MSK_IAM_REFRESH
 *
 * @locality Application thread
 */
static rd_kafka_op_res_t
rd_kafka_aws_msk_iam_refresh_op (rd_kafka_t *rk,
                                 rd_kafka_q_t *rkq,
                                 rd_kafka_op_t *rko) {
        /* The op callback is invoked when the op is destroyed via
         * rd_kafka_op_destroy() or rd_kafka_event_destroy(), so
         * make sure we don't refresh upon destruction since
         * the op has already been handled by this point.
         */
        rd_kafka_aws_msk_iam_credential_refresh(rk, rk->rk_conf.opaque);
        return RD_KAFKA_OP_RES_HANDLED;
}

/**
 * @brief Enqueue a credential refresh.
 * @locks rwlock_wrlock(&handle->lock) MUST be held
 */
static void rd_kafka_aws_msk_iam_enqueue_credential_refresh (
        rd_kafka_sasl_aws_msk_iam_handle_t *handle) {
        rd_kafka_op_t *rko;

        rko = rd_kafka_op_new_cb(handle->rk, RD_KAFKA_OP_AWS_MSK_IAM_REFRESH,
                                 rd_kafka_aws_msk_iam_refresh_op);
        rd_kafka_op_set_prio(rko, RD_KAFKA_PRIO_FLASH);
        handle->wts_enqueued_refresh = rd_uclock();
        rd_kafka_q_enq(handle->rk->rk_rep, rko);
}

/**
 * @brief Enqueue a credential refresh if necessary.
 *
 * The method rd_kafka_aws_msk_iam_enqueue_credential_refresh() is invoked
 * if necessary; the required lock is acquired and released.  This method
 * returns immediately when SASL/AWS_MSK_IAM is not in use by the client.
 */
static void
rd_kafka_aws_msk_iam_enqueue_credential_refresh_if_necessary (
        rd_kafka_sasl_aws_msk_iam_handle_t *handle) {
        rd_ts_t now_wallclock;

        now_wallclock = rd_uclock();

        rwlock_wrlock(&handle->lock);
        if (handle->wts_refresh_after < now_wallclock &&
            handle->wts_enqueued_refresh <= handle->wts_refresh_after) {
                rd_kafka_aws_msk_iam_enqueue_credential_refresh(handle);
        }
        rwlock_wrunlock(&handle->lock);
}

/**
 * @brief Build client first message
 *
 *        Builds the first message for the payload
 *        by combining canonical request, signature, and credentials.
 *
 * @remark out->ptr is allocated and will need to be freed.
 */
static void
rd_kafka_sasl_aws_msk_iam_build_client_first_message (
        rd_kafka_transport_t *rktrans,
        rd_chariov_t *out) {
        struct rd_kafka_sasl_aws_msk_iam_state *state = rktrans->rktrans_sasl.state;

        char *aws_service = "kafka-cluster";
        char *algorithm = "AWS4-HMAC-SHA256";
        char *signed_headers = "host";
        char *method = "GET";
        char *request_parameters = "";
        char *action = "kafka-cluster:Connect";

        time_t t = time(&t);
        struct tm *tmp = gmtime(&t);  // must use UTC time
        char *ymd = rd_malloc(sizeof(char) * 9);
        char *hms = rd_malloc(sizeof(char) * 7);
        strftime(ymd, sizeof(char) * 9, "%Y%m%d", tmp);
        strftime(hms, sizeof(char) * 7, "%H%M%S", tmp);

        rd_kafka_dbg(rktrans->rktrans_rkb->rkb_rk, SECURITY, "SASLAWSMSKIAM", "Sending first message for auth using creds: %s", state->aws_access_key_id);

        char *canonical_querystring = rd_kafka_aws_build_sasl_canonical_querystring(
                action,
                state->aws_access_key_id,
                state->aws_region,
                ymd,
                hms,
                aws_service,
                state->aws_security_token
        );

        str_builder_t *sb;
        sb = str_builder_create();
        str_builder_add_str(sb, "host:");
        str_builder_add_str(sb, state->hostname);
        char *canonical_headers = str_builder_dump(sb);
        str_builder_destroy(sb);

        char *sasl_payload = rd_kafka_aws_build_sasl_payload(ymd,
                                                        hms,
                                                        state->hostname,
                                                        state->aws_access_key_id,
                                                        state->aws_secret_access_key,
                                                        state->aws_security_token,
                                                        state->aws_region,
                                                        aws_service,
                                                        method,
                                                        algorithm,
                                                        canonical_headers,
                                                        canonical_querystring,
                                                        signed_headers,
                                                        request_parameters,
                                                        state->md);
        rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY,
                           "SASLAWSMSKIAM",
                           "SASL payload calculated as %s",
                           sasl_payload);

        /* Save JSON to out pointer for sending */
        out->size = strlen(sasl_payload);
        out->ptr = rd_malloc(out->size + 1);

        rd_snprintf(out->ptr, out->size + 1,
                    "%s", sasl_payload);

        RD_IF_FREE(ymd, rd_free);
        RD_IF_FREE(hms, rd_free);
        RD_IF_FREE(canonical_querystring, rd_free);
        RD_IF_FREE(canonical_headers, rd_free);
        RD_IF_FREE(sasl_payload, rd_free);
}

/**
 * @brief Handle server-response
 *
 *        This is the end of authentication and the AWS MSK IAM state
 *        will be freed at the end of this function regardless of
 *        authentication outcome.
 *
 * @returns -1 on failure
 */
static int
rd_kafka_sasl_aws_msk_iam_handle_server_response (
        rd_kafka_transport_t *rktrans,
        const rd_chariov_t *in,
        char *errstr, size_t errstr_size) {
        if (in->size) {
            rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY | RD_KAFKA_DBG_BROKER, "SASLAWSMSKIAM",
                           "Received non-empty SASL AWS MSK IAM (builtin) "
                           "response from broker (%s)", in->ptr);
            rd_kafka_sasl_auth_done(rktrans);
            return 0;
        } else {
            rd_snprintf(errstr, errstr_size,
                        "SASL AWS MSK IAM authentication failed: "
                        "Broker response: %s", in->ptr);
            return -1;
        }
}

/**
 * @brief SASL AWS MSK IAM client state machine
 * @returns -1 on failure (errstr set), else 0.
 */
static int rd_kafka_sasl_aws_msk_iam_fsm (rd_kafka_transport_t *rktrans,
                                    const rd_chariov_t *in,
                                    char *errstr, size_t errstr_size) {
        static const char *state_names[] = {
                    "client-first-message",
                    "server-response",
        };
        struct rd_kafka_sasl_aws_msk_iam_state *state = rktrans->rktrans_sasl.state;
        rd_chariov_t out = RD_ZERO_INIT;
        int r = -1;
        rd_ts_t ts_start = rd_clock();
        int prev_state = state->state;

        rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY | RD_KAFKA_DBG_BROKER, "SASLAWSMSKIAM",
                   "SASL AWS MSK IAM client in state %s",
                   state_names[state->state]);

        switch (state->state)
        {
        case RD_KAFKA_SASL_AWS_MSK_IAM_SEND_CLIENT_FIRST_MESSAGE:
            rd_assert(!in); /* Not expecting any server-input */

            rd_kafka_sasl_aws_msk_iam_build_client_first_message(rktrans, &out);
            state->state = RD_KAFKA_SASL_AWS_MSK_IAM_RECEIVE_SERVER_RESPONSE;
            break;
        case RD_KAFKA_SASL_AWS_MSK_IAM_RECEIVE_SERVER_RESPONSE:
            rd_assert(in);  /* Requires server-input */
            r = rd_kafka_sasl_aws_msk_iam_handle_server_response(
                        rktrans, in, errstr, errstr_size);
            break;
        }

        if (out.ptr) {
                r = rd_kafka_sasl_send(rktrans, out.ptr, (int)out.size,
                                       errstr, errstr_size);
                RD_IF_FREE(out.ptr, rd_free);
        }

        ts_start = (rd_clock() - ts_start) / 1000;
        if (ts_start >= 100) {
                rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY | RD_KAFKA_DBG_BROKER, "SASLAWSMSKIAM",
                           "SASL AWS MSK IAM state %s handled in %"PRId64"ms",
                           state_names[prev_state], ts_start);
        }

        return r;
}

/**
 * @brief Handle received frame from broker.
 */
static int rd_kafka_sasl_aws_msk_iam_recv (rd_kafka_transport_t *rktrans,
                                     const void *buf, size_t size,
                                     char *errstr, size_t errstr_size) {
        const rd_chariov_t in = { .ptr = (char *)buf, .size = size };
        return rd_kafka_sasl_aws_msk_iam_fsm(rktrans, &in, errstr, errstr_size);
}

/**
 * @brief Initialize and start SASL AWS MSK IAM (builtin) authentication.
 *
 * Returns 0 on successful init and -1 on error.
 *
 * @locality broker thread
 */
static int rd_kafka_sasl_aws_msk_iam_client_new (rd_kafka_transport_t *rktrans,
                                    const char *hostname,
                                    char *errstr, size_t errstr_size) {
        rd_kafka_sasl_aws_msk_iam_handle_t *handle =
                rktrans->rktrans_rkb->rkb_rk->rk_sasl.handle;
        struct rd_kafka_sasl_aws_msk_iam_state *state;

        rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY | RD_KAFKA_DBG_BROKER, "SASLAWSMSKIAM",
                   "SASL AWS MSK IAM new client initializing");

        state = rd_calloc(1, sizeof(*state));
        state->state = RD_KAFKA_SASL_AWS_MSK_IAM_SEND_CLIENT_FIRST_MESSAGE;

        /*
         * Save off the state structure now, before any possibility of
         * returning, so that we will always free up the allocated memory in
         * rd_kafka_sasl_aws_msk_iam_close().
         */
        rktrans->rktrans_sasl.state = state;

        /*
         * Make sure we have a consistent view of the token and extensions
         * throughout the authentication process -- even if it is refreshed
         * midway through this particular authentication.
         */
        rwlock_rdlock(&handle->lock);
        if (!handle->aws_access_key_id || !handle->aws_secret_access_key || !handle->aws_region) {
                rd_snprintf(errstr, errstr_size,
                            "AWS_MSK_IAM cannot log in because there "
                            "is no credentials available; last error: %s",
                            handle->errstr ?
                            handle->errstr : "(not available)");
                rwlock_rdunlock(&handle->lock);
                return -1;
        }
        state->hostname = (char *)hostname;
        state->md = EVP_get_digestbyname("SHA256");

        state->aws_access_key_id = rd_strdup(handle->aws_access_key_id);
        state->aws_secret_access_key = rd_strdup(handle->aws_secret_access_key);
        state->aws_region = rd_strdup(handle->aws_region);
        if (handle->aws_security_token) {
                state->aws_security_token = rd_strdup(handle->aws_security_token);
        }
        else {
                state->aws_security_token = NULL;
        }
        rwlock_rdunlock(&handle->lock);
        /* Kick off the FSM */
        return rd_kafka_sasl_aws_msk_iam_fsm(rktrans, NULL, errstr, errstr_size);
}

/**
 * @brief Credential refresh timer callback.
 *
 * @locality rdkafka main thread
 */
static void
rd_kafka_sasl_aws_msk_iam_credential_refresh_tmr_cb (rd_kafka_timers_t *rkts,
                                                void *arg) {
        rd_kafka_t *rk = arg;
        rd_kafka_sasl_aws_msk_iam_handle_t *handle = rk->rk_sasl.handle;

        /* Enqueue a token refresh if necessary */
        rd_kafka_aws_msk_iam_enqueue_credential_refresh_if_necessary(handle);
}


/**
 * @brief Per-client-instance initializer
 */
static int rd_kafka_sasl_aws_msk_iam_init (rd_kafka_t *rk,
                                           char *errstr, size_t errstr_size) {
        rd_kafka_sasl_aws_msk_iam_handle_t *handle;
        const rd_kafka_conf_t *conf = &rk->rk_conf;

        handle = rd_calloc(1, sizeof(*handle));
        rk->rk_sasl.handle = handle;

        rwlock_init(&handle->lock);

        handle->rk = rk;

        rd_kafka_timer_start(&rk->rk_timers, &handle->credential_refresh_tmr,
                             1 * 1000 * 1000,
                             rd_kafka_sasl_aws_msk_iam_credential_refresh_tmr_cb,
                             rk);

        rd_kafka_dbg(rk, SECURITY, "SASLAWSMSKIAM", "Enqueuing credential refresh");

        // Set initial handle creds which will be passed into *state in client_new()
        /* Check if SASL/AWS_MSK_IAM is the configured auth mechanism */
        if (rk->rk_conf.sasl.provider != &rd_kafka_sasl_aws_msk_iam_provider ||
            !handle) {
                rd_snprintf(errstr, errstr_size, "SASL/AWS_MSK_IAM is not the "
                            "configured authentication mechanism");
                return RD_KAFKA_RESP_ERR__STATE;
        }

        if (rk->rk_conf.sasl.aws_refresh_kind == AWS_REFRESH_NO_REFRESH) {
                rwlock_wrlock(&handle->lock);
                handle->aws_access_key_id = rd_strdup(conf->sasl.aws_access_key_id);
                handle->aws_secret_access_key = rd_strdup(conf->sasl.aws_secret_access_key);
                handle->aws_region = rd_strdup(conf->sasl.aws_region);
                if (conf->sasl.aws_security_token) {
                        handle->aws_security_token = rd_strdup(conf->sasl.aws_security_token);
                }
                else {
                        handle->aws_security_token = NULL;
                }

                rwlock_wrunlock(&handle->lock);
                rd_kafka_all_brokers_wakeup(rk, RD_KAFKA_BROKER_STATE_TRY_CONNECT, "AWS IAM Creds reloaded");
        }
        else if (rk->rk_conf.sasl.aws_refresh_kind == AWS_REFRESH_METADATA) {
                if (rd_kafka_aws_refresh_with_metadata(rk, errstr, errstr_size) != 0) {
                        return RD_KAFKA_RESP_ERR__STATE;
                }
        } else if (rk->rk_conf.sasl.aws_refresh_kind == AWS_REFRESH_WEB_IDENTITY_TOKEN_FILE) {
                if (rd_kafka_aws_refresh_with_web_identity_token_file(rk, errstr, errstr_size) != 0) {
                        return RD_KAFKA_RESP_ERR__STATE;
                }
        } else {
                rd_snprintf(errstr, errstr_size, "Wrong aws refresh kind: %d",rk->rk_conf.sasl.aws_refresh_kind);
                return RD_KAFKA_RESP_ERR__STATE;
        }

        handle->errstr = NULL;

        return 0;
}

/**
 * @brief Per-client-instance destructor
 */
static void rd_kafka_sasl_aws_msk_iam_term (rd_kafka_t *rk) {
        rd_kafka_sasl_aws_msk_iam_handle_t *handle = rk->rk_sasl.handle;

        if (!handle) {
                return;
        }
        if (handle->aws_access_key_id) {
                rd_kafka_dbg(rk, SECURITY, "SASLAWSMSKIAM", "Termination of SASL session: %s", handle->aws_access_key_id);
        }

        rk->rk_sasl.handle = NULL;

        rd_kafka_timer_stop(&rk->rk_timers, &handle->credential_refresh_tmr, 1);

        RD_IF_FREE(handle->aws_access_key_id, rd_free);
        RD_IF_FREE(handle->aws_secret_access_key, rd_free);
        RD_IF_FREE(handle->aws_region, rd_free);
        RD_IF_FREE(handle->aws_security_token, rd_free);
        RD_IF_FREE(handle->errstr, rd_free);

        rwlock_destroy(&handle->lock);

        rd_free(handle);
}

/**
 * @brief Close and free authentication state
 */
static void rd_kafka_sasl_aws_msk_iam_close (rd_kafka_transport_t *rktrans) {
        struct rd_kafka_sasl_aws_msk_iam_state *state = 
                rktrans->rktrans_sasl.state;

        if (!state) {
                return;
        }

        rd_free(state);
}

/**
 * @brief Validate AWS MSK IAM config and look up the hash function
 */
static int rd_kafka_sasl_aws_msk_iam_conf_validate (rd_kafka_t *rk,
                                              char *errstr,
                                              size_t errstr_size) {
        rk->rk_conf.sasl.aws_refresh_kind = AWS_REFRESH_NO_REFRESH;
        if (!rk->rk_conf.sasl.aws_region && getenv("AWS_REGION")) {
                rk->rk_conf.sasl.aws_region = rd_strdup(getenv("AWS_REGION"));
        }
        if (!rk->rk_conf.sasl.aws_region && getenv("AWS_DEFAULT_REGION")) {
                rk->rk_conf.sasl.aws_region = rd_strdup(getenv("AWS_DEFAULT_REGION"));
        }
        if (!rk->rk_conf.sasl.aws_access_key_id && getenv("AWS_ACCESS_KEY_ID")) {
                rk->rk_conf.sasl.aws_access_key_id = rd_strdup(getenv("AWS_ACCESS_KEY_ID"));
        }
        if (!rk->rk_conf.sasl.aws_secret_access_key && getenv("AWS_SECRET_ACCESS_KEY")) {
                rk->rk_conf.sasl.aws_secret_access_key = rd_strdup(getenv("AWS_SECRET_ACCESS_KEY"));
        }
        if (!rk->rk_conf.sasl.aws_security_token && getenv("AWS_SECURITY_TOKEN")) {
                rk->rk_conf.sasl.aws_security_token = rd_strdup(getenv("AWS_SECURITY_TOKEN"));
        }
        if (!rk->rk_conf.sasl.aws_role_arn && getenv("AWS_ROLE_ARN")) {
                rk->rk_conf.sasl.aws_role_arn = rd_strdup(getenv("AWS_ROLE_ARN"));
        }
        if (!rk->rk_conf.sasl.aws_role_session_name) {
                rk->rk_conf.sasl.aws_role_session_name = rd_strdup("librdkafka");
        }
        if (!rk->rk_conf.sasl.aws_web_identity_token_file && getenv("AWS_WEB_IDENTITY_TOKEN_FILE")) {
                rk->rk_conf.sasl.aws_web_identity_token_file = rd_strdup(getenv("AWS_WEB_IDENTITY_TOKEN_FILE"));
        }
        if (!rk->rk_conf.sasl.aws_region) {
                rd_kafka_dbg(rk, SECURITY, "BRKMAIN", "No AWS Region provided, trying to get it from metadata API");
                char * region = rd_kafka_aws_region_from_metadata(errstr, errstr_size);
                if (region != NULL) {
                        rk->rk_conf.sasl.aws_region = rd_strdup(region);
                        RD_IF_FREE(region, rd_free);
                }
        }
        if (!rk->rk_conf.sasl.aws_region) {
                        rd_snprintf(errstr, errstr_size,
                            "sasl.aws_region must be set or exists in the environment ($AWS_DEFAULT_REGION or metadata api)");
                return -1;
        }
        if ((!rk->rk_conf.sasl.aws_access_key_id || !rk->rk_conf.sasl.aws_secret_access_key) && rk->rk_conf.sasl.aws_role_arn && rk->rk_conf.sasl.aws_web_identity_token_file) {
                if (access(rk->rk_conf.sasl.aws_web_identity_token_file, F_OK) == 0) {
                        rd_kafka_dbg(rk, SECURITY, "BRKMAIN", "Enabling AWS Authen using web identity token file from file %s", rk->rk_conf.sasl.aws_web_identity_token_file);
                        rk->rk_conf.sasl.aws_refresh_kind = AWS_REFRESH_WEB_IDENTITY_TOKEN_FILE;
                        return 0;
                }
        }
        if (!rk->rk_conf.sasl.aws_access_key_id || !rk->rk_conf.sasl.aws_secret_access_key) {
                rd_kafka_dbg(rk, SECURITY, "BRKMAIN", "No AWS Credentials provided, trying to get credentials from metadata API");
                rd_kafka_aws_credential_t credential;
                if (rd_kafka_aws_credentials_from_metadata(&credential, errstr, errstr_size) == 0) {
                        rk->rk_conf.sasl.aws_refresh_kind = AWS_REFRESH_METADATA;
                        rd_kafka_dbg(rk, SECURITY, "BRKMAIN", "AWD Credentials found in the metadata API");
                        rd_kafka_sasl_aws_msk_iam_credential_free(&credential);
                        return 0;
                }
        }
        if (!rk->rk_conf.sasl.aws_access_key_id || !rk->rk_conf.sasl.aws_secret_access_key) {
                rd_snprintf(errstr, errstr_size,
                            "sasl.aws_access_key_id, sasl.aws_secret_access_key, and sasl.aws_region must be set");
                return -1;
        }

        return 0;
}

const struct rd_kafka_sasl_provider rd_kafka_sasl_aws_msk_iam_provider = {
        .name           = "AWS_MSK_IAM",
        .init           = rd_kafka_sasl_aws_msk_iam_init,
        .term           = rd_kafka_sasl_aws_msk_iam_term,
        .client_new     = rd_kafka_sasl_aws_msk_iam_client_new,
        .recv           = rd_kafka_sasl_aws_msk_iam_recv,
        .close          = rd_kafka_sasl_aws_msk_iam_close,
        .conf_validate  = rd_kafka_sasl_aws_msk_iam_conf_validate,
};

/**
 * @name Unit tests
 */

int unittest_aws_msk_iam (void) {
        int fails = 0;

        return fails;
}
