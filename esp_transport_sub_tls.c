#include <esp_tls.h>
#include <esp_log.h>
#include <esp_tls_mbedtls.h>
#include "esp_transport_internal.h"
#include "esp_transport_sub_tls.h"

static const char *TAG = "trans_sub_tls";

typedef struct transport_sub_tls {
    int sock_fd;
    esp_tls_t *tls;
    esp_tls_cfg_t cfg;
    esp_transport_handle_t parent;
} transport_sub_tls_t;

/*
 * Check if the requested operation would be blocking on a non-blocking socket
 * and thus 'failed' with a negative return value.
 *
 * Note: on a blocking socket this function always returns 0!
 */
static int sub_tls_net_would_block(const mbedtls_net_context *ctx)
{
    int error = errno;

    switch (errno = error) {
#if defined EAGAIN
        case EAGAIN:
#endif
#if defined EWOULDBLOCK && EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            return 1;
    }
    return 0;
}

// Remember the ctx here is transport_sub_tls_t!!
static int mbedtls_over_tcp_trans_recv(void *ctx, unsigned char *buf, size_t len)
{
    if (ctx == NULL) {
        ESP_LOGE(TAG, "Context is null");
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }


    transport_sub_tls_t *handle = (transport_sub_tls_t *)ctx;
    ESP_LOGD(TAG, "Recv: ctx %p, buf %p, len %d", ctx, buf, len);

    int ret = esp_transport_read(handle->parent, (char *)buf, (int)len, handle->cfg.timeout_ms);

    ESP_LOGD(TAG, "Recv: done, ret %d", ret);

    if ( ret < 0 ) {
        if (sub_tls_net_would_block(ctx) != 0) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }

        if (errno == EPIPE || errno == ECONNRESET) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }

        if (errno == EINTR) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }

        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    return ret;
}

// Remember the ctx here is transport_sub_tls_t!!
static int mbedtls_over_tcp_trans_send(void *ctx, const unsigned char *buf, size_t len)
{
    if (ctx == NULL) {
        ESP_LOGE(TAG, "Context is null");
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }

    transport_sub_tls_t *handle = (transport_sub_tls_t *)ctx;
    ESP_LOGD(TAG, "Send: ctx %p, parent %p, buf %p, len %d", ctx, handle->parent, buf, len);

    int ret = esp_transport_write(handle->parent, (const char *)buf, (int)len, handle->cfg.timeout_ms);

    ESP_LOGD(TAG, "Send: done, ret %d", ret);

    if (ret < 0) {
        if (sub_tls_net_would_block(ctx) != 0) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }

        if (errno == EPIPE || errno == ECONNRESET) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }

        if (errno == EINTR) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }

        return MBEDTLS_ERR_NET_SEND_FAILED;
    }

    return ret;
}

/* This function shall return the error message when appropriate log level has been set, otherwise this function shall do nothing */
static void sub_tls_mbedtls_print_error_msg(int error)
{
#if (CONFIG_LOG_DEFAULT_LEVEL_DEBUG || CONFIG_LOG_DEFAULT_LEVEL_VERBOSE)
    static char error_buf[100];
    mbedtls_strerror(error, error_buf, sizeof(error_buf));
    ESP_LOGI(TAG, "(%04X): %s", error, error_buf);
#endif
}

static esp_err_t sub_tls_create_mbedtls_handle(const char *hostname, size_t hostlen, const void *cfg, esp_tls_t *tls, transport_sub_tls_t *sub_tls_handle)
{
    assert(cfg != NULL);
    assert(tls != NULL);
    int ret;
    esp_err_t esp_ret = ESP_FAIL;

#ifdef CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to initialize PSA crypto, returned %d\n", (int) status);
        return esp_ret;
    }
#endif // CONFIG_MBEDTLS_SSL_PROTO_TLS1_3

    tls->server_fd.fd = tls->sockfd;
    mbedtls_ssl_init(&tls->ssl);
    mbedtls_ctr_drbg_init(&tls->ctr_drbg);
    mbedtls_ssl_config_init(&tls->conf);
    mbedtls_entropy_init(&tls->entropy);

    if (tls->role == ESP_TLS_CLIENT) {
        esp_ret = set_client_config(hostname, hostlen, (esp_tls_cfg_t *)cfg, tls);
        if (esp_ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to set client configurations, returned [0x%04X] (%s)", esp_ret, esp_err_to_name(esp_ret));
            goto exit;
        }
    } else if (tls->role == ESP_TLS_SERVER) {
#ifdef CONFIG_ESP_TLS_SERVER
        esp_ret = set_server_config((esp_tls_cfg_server_t *) cfg, tls);
        if (esp_ret != 0) {
            ESP_LOGE(TAG, "Failed to set server configurations, returned [0x%04X] (%s)", esp_ret, esp_err_to_name(esp_ret));
            goto exit;
        }
#else
        ESP_LOGE(TAG, "ESP_TLS_SERVER Not enabled in Kconfig");
        goto exit;
#endif
    }

    if ((ret = mbedtls_ctr_drbg_seed(&tls->ctr_drbg,
                                     mbedtls_entropy_func, &tls->entropy, NULL, 0)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned -0x%04X", -ret);
        sub_tls_mbedtls_print_error_msg(ret);
        esp_ret = ESP_ERR_MBEDTLS_CTR_DRBG_SEED_FAILED;
        goto exit;
    }

    mbedtls_ssl_set_user_data_p(&tls->ssl, sub_tls_handle);
    mbedtls_ssl_conf_rng(&tls->conf, mbedtls_ctr_drbg_random, &tls->ctr_drbg);

#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&tls->conf, CONFIG_MBEDTLS_DEBUG_LEVEL);
#endif

#ifdef CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
    mbedtls_ssl_conf_min_tls_version(&tls->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&tls->conf, MBEDTLS_SSL_VERSION_TLS1_3);
#endif

    if ((ret = mbedtls_ssl_setup(&tls->ssl, &tls->conf)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%04X", -ret);
        sub_tls_mbedtls_print_error_msg(ret);
        esp_ret = ESP_ERR_MBEDTLS_SSL_SETUP_FAILED;
        goto exit;
    }
    mbedtls_ssl_set_bio(&tls->ssl, sub_tls_handle, mbedtls_over_tcp_trans_send, mbedtls_over_tcp_trans_recv, NULL);

    return ESP_OK;

exit:
    esp_mbedtls_cleanup(tls);
    return esp_ret;
}

static int sub_tls_connect(esp_transport_handle_t transport, const char *const host, int port, int timeout_ms)
{
    transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL || handle->parent == NULL || handle->parent->_get_socket == NULL) {
        ESP_LOGE(TAG, "Unsupported parent transport");
        ESP_LOGE(TAG, "Handle: %p", handle);
        if (handle->parent) ESP_LOGE(TAG, "Handle parent: %p, get_socket %p", handle->parent, handle->parent->_get_socket);
        return -1;
    }

    int conn_ret = esp_transport_connect(handle->parent, host, port, timeout_ms);
    if (conn_ret < 0) {
        ESP_LOGE(TAG, "Failed to perform parent connect: %d", conn_ret);
        return conn_ret;
    }

    int sock_fd = handle->parent->_get_socket(handle->parent);
    if (sock_fd < 0) {
        ESP_LOGE(TAG, "Invalid socket FD value: %d", sock_fd);
        return sock_fd;
    }

    handle->tls = esp_tls_init();
    if (handle->tls == NULL) {
        ESP_LOGE(TAG, "Failed to create TLS context");
        return -2;
    }

    // Now we create our custom magic mbedTLS handle
    esp_err_t ret = sub_tls_create_mbedtls_handle(host, strlen(host), (void *)&handle->cfg, handle->tls, handle);
    handle->tls->read = esp_mbedtls_read;
    handle->tls->write = esp_mbedtls_write;
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed when creating mbedTLS handle: 0x%x", ret);
        return ret;
    }

    // Here we assume we have a connection already, and we "fast-track" the state to handshake only
    ret = esp_tls_set_conn_state(handle->tls, ESP_TLS_HANDSHAKE);

    // We also manually provide the socket FD to esp-tls to let it does its job
    ret = ret ?: esp_tls_set_conn_sockfd(handle->tls, sock_fd);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed when setting up ESP-TLS state: 0x%x", ret);
        return -3;
    }

    ESP_LOGI(TAG, "TLS connecting to host %s; port %d", host, port);
    conn_ret = esp_tls_conn_new_sync(host, (int)strlen(host), port, &handle->cfg, handle->tls);
    if (conn_ret != 1) {
        ESP_LOGE(TAG, "TLS setup/handshake failed: %d", conn_ret);
        return -4;
    }

    return 0;
}

static int sub_tls_close(esp_transport_handle_t transport)
{
    ESP_LOGD(TAG, "TLS closing!");
    transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        return -1;
    }

    int ret = esp_transport_close(handle->parent);
    if (ret >= 0) {
        handle->tls = NULL;
    }

    return ret;
}

static int sub_tls_write(esp_transport_handle_t transport, const char *buffer, int len, int timeout_ms)
{
    int poll;
    transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        return -1;
    }

    int ret = esp_tls_conn_write(handle->tls, (const unsigned char *) buffer, len);
    if (ret < 0) {
        ESP_LOGE(TAG, "esp_tls_conn_write error, errno=%s", strerror(errno));
        esp_tls_error_handle_t esp_tls_error_handle;
        if (esp_tls_get_error_handle(handle->tls, &esp_tls_error_handle) == ESP_OK) {
            ESP_LOGE(TAG, "TLS-level error: last error 0x%x, %s; TLS error code %d; TLS flag %d",
                     esp_tls_error_handle->last_error,
                     esp_err_to_name(esp_tls_error_handle->last_error),
                     esp_tls_error_handle->esp_tls_error_code,
                     esp_tls_error_handle->esp_tls_flags);
            esp_transport_set_errors(transport, esp_tls_error_handle);
        } else {
            ESP_LOGE(TAG, "Error in obtaining the error handle");
        }
    }
    return ret;
}

static int sub_tls_read(esp_transport_handle_t transport, char *buffer, int len, int timeout_ms)
{
    transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        return -1;
    }

    int ret = esp_tls_conn_read(handle->tls, (unsigned char *)buffer, len);
    if (ret < 0) {
        ESP_LOGE(TAG, "esp_tls_conn_read error, errno=%s", strerror(errno));
        if (ret == ESP_TLS_ERR_SSL_WANT_READ || ret == ESP_TLS_ERR_SSL_TIMEOUT) {
            ret = ERR_TCP_TRANSPORT_CONNECTION_TIMEOUT;
        }

        esp_tls_error_handle_t esp_tls_error_handle;
        if (esp_tls_get_error_handle(handle->tls, &esp_tls_error_handle) == ESP_OK) {
            esp_transport_set_errors(transport, esp_tls_error_handle);
        } else {
            ESP_LOGE(TAG, "Error in obtaining the error handle");
        }
    } else if (ret == 0) {
        if (poll > 0) {
            // no error, socket reads 0 while previously detected as readable -> connection has been closed cleanly
            capture_tcp_transport_error(transport, ERR_TCP_TRANSPORT_CONNECTION_CLOSED_BY_FIN);
        }
        ret = ERR_TCP_TRANSPORT_CONNECTION_CLOSED_BY_FIN;
    }

    return ret;
}

static int sub_tls_poll_read(esp_transport_handle_t transport, int timeout_ms)
{
    transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        return -1;
    }

    return esp_transport_poll_read(handle->parent, handle->cfg.timeout_ms > timeout_ms ? handle->cfg.timeout_ms : timeout_ms);
}

static int sub_tls_poll_write(esp_transport_handle_t transport, int timeout_ms)
{
    transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        return -1;
    }

    return esp_transport_poll_write(handle->parent, handle->cfg.timeout_ms > timeout_ms ? handle->cfg.timeout_ms : timeout_ms);
}

static esp_err_t sub_tls_destroy(esp_transport_handle_t transport)
{
    ESP_LOGD(TAG, "Destroying!");
    if (transport == NULL) {
        return ESP_OK;
    }

    transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
    ESP_LOGI(TAG, "Handle %p destroyed!", handle);
    if (handle == NULL) {
        return ESP_OK; // Might have been freed before??
    } else {
        if (handle->tls) {
            esp_tls_conn_destroy(handle->tls);
            handle->tls = NULL;
        }
    }

    return ESP_OK;
}

static int sub_tls_get_sockfd(esp_transport_handle_t transport)
{
    if (transport) {
        transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
        if (handle && handle->parent && handle->parent->_get_socket) {
            return handle->parent->_get_socket(handle->parent);
        }
    }

    return -1;
}

esp_err_t esp_transport_sub_tls_init(esp_transport_handle_t *new_handle, esp_transport_handle_t parent_handle, const esp_transport_sub_tls_config_t *config)
{
    if (new_handle == NULL || parent_handle == NULL || config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_transport_handle_t transport = esp_transport_init();
    if (transport == NULL) {
        ESP_LOGE(TAG, "Failed to create transport handle");
        return ESP_FAIL;
    }

    // This is a workaround for WebSocket transport
    if (parent_handle->foundation == NULL) {
        transport->foundation = esp_transport_init_foundation_transport();
    } else {
        transport->foundation = parent_handle->foundation;
    }

    transport_sub_tls_t *handle = calloc(1, sizeof(transport_sub_tls_t));
    if (handle == NULL) {
        ESP_LOGE(TAG, "Failed to create transport context");
        esp_transport_destroy(transport);
        return ESP_ERR_NO_MEM;
    } else {
        esp_transport_set_context_data(transport, handle);
    }

    transport->_get_socket = sub_tls_get_sockfd;
    esp_transport_set_func(transport, sub_tls_connect, sub_tls_read, sub_tls_write, sub_tls_close, sub_tls_poll_read, sub_tls_poll_write, sub_tls_destroy);

    if (config->use_global_ca_store == true) {
        handle->cfg.use_global_ca_store = true;
    } else if (config->cert) {
        if (!config->cert_len) {
            handle->cfg.cacert_pem_buf = (void *)config->cert;
            handle->cfg.cacert_pem_bytes = strlen(config->cert) + 1;
        } else {
            handle->cfg.cacert_buf = (void *)config->cert;
            handle->cfg.cacert_bytes = config->cert_len;
        }
    }

    if (config->client_cert) {
        if (!config->client_cert_len) {
            handle->cfg.clientcert_pem_buf = (void *)config->client_cert;
            handle->cfg.clientcert_pem_bytes = strlen(config->client_cert) + 1;
        } else {
            handle->cfg.clientcert_buf = (void *)config->client_cert;
            handle->cfg.clientcert_bytes = config->client_cert_len;
        }
    }

    if (config->client_key) {
        if (!config->client_key_len) {
            handle->cfg.clientkey_pem_buf = (void *)config->client_key;
            handle->cfg.clientkey_pem_bytes = strlen(config->client_key) + 1;
        } else {
            handle->cfg.clientkey_buf = (void *)config->client_key;
            handle->cfg.clientkey_bytes = config->client_key_len;
        }
    }

    if (config->crt_bundle_attach) {
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
        handle->cfg.crt_bundle_attach = config->crt_bundle_attach;
#else //CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
        ESP_LOGE(TAG, "crt_bundle_attach configured but not enabled in menuconfig: Please enable MBEDTLS_CERTIFICATE_BUNDLE option");
#endif
    }

    handle->cfg.skip_common_name = config->skip_cert_common_name_check;
    handle->cfg.timeout_ms = config->timeout_ms;
    handle->cfg.is_plain_tcp = false; // Does this really matter??
    handle->cfg.non_block = true; // Seems like this is needed - otherwise it will do the select() crap
    handle->parent = parent_handle;

    *new_handle = transport;
    return ESP_OK;
}
