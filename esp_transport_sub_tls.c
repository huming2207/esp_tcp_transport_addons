#include <esp_tls.h>
#include <esp_log.h>
#include <esp_tls_mbedtls.h>
#include <esp_crt_bundle.h>
#include "esp_transport_internal.h"
#include "esp_transport_sub_tls.h"

static const char *TAG = "trans_sub_tls";

typedef struct transport_sub_tls {
    mbedtls_ssl_context ssl;                                                    /*!< TLS/SSL context */
    mbedtls_entropy_context entropy;                                            /*!< mbedTLS entropy context structure */
    mbedtls_ctr_drbg_context ctr_drbg;                                          /*!< mbedTLS ctr drbg context structure.
                                                                                     CTR_DRBG is deterministic random
                                                                                     bit generation based on AES-256 */
    mbedtls_ssl_config conf;                                                    /*!< TLS/SSL configuration to be shared
                                                                                     between mbedtls_ssl_context
                                                                                     structures */
    mbedtls_net_context server_fd;                                              /*!< mbedTLS wrapper type for sockets */
    mbedtls_x509_crt cacert;                                                    /*!< Container for the X.509 CA certificate */
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

static esp_err_t sub_tls_create_mbedtls_handle(const char *hostname, transport_sub_tls_t *sub_tls_handle, bool use_esp_crt_bundle)
{

    if (sub_tls_handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    int ret;
    esp_err_t esp_ret = ESP_FAIL;

#ifdef CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to initialize PSA crypto, returned %d\n", (int) status);
        return esp_ret;
    }
#endif // CONFIG_MBEDTLS_SSL_PROTO_TLS1_3

    mbedtls_ssl_init(&sub_tls_handle->ssl);
    mbedtls_x509_crt_init(&sub_tls_handle->cacert);
    mbedtls_ctr_drbg_init(&sub_tls_handle->ctr_drbg);
    mbedtls_ssl_config_init(&sub_tls_handle->conf);
    mbedtls_entropy_init(&sub_tls_handle->entropy);

    if (use_esp_crt_bundle) {
        ret = esp_crt_bundle_attach(&sub_tls_handle->conf);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to attach crt bundle! 0x%x", ret);
            return ret;
        }
    }

    ret = mbedtls_ssl_set_hostname(&sub_tls_handle->ssl, hostname);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname failed: -0x%x", ret);
        return ESP_FAIL;
    }

    if((ret = mbedtls_ssl_config_defaults(&sub_tls_handle->conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        return ESP_FAIL;
    }

    mbedtls_ssl_conf_authmode(&sub_tls_handle->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&sub_tls_handle->conf, &sub_tls_handle->cacert, NULL);
    mbedtls_ssl_conf_rng(&sub_tls_handle->conf, mbedtls_ctr_drbg_random, &sub_tls_handle->ctr_drbg);
#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&sub_tls_handle->conf, CONFIG_MBEDTLS_DEBUG_LEVEL);
#endif

    if ((ret = mbedtls_ctr_drbg_seed(&sub_tls_handle->ctr_drbg, mbedtls_entropy_func, &sub_tls_handle->entropy, NULL, 0)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned -0x%04X", -ret);
        sub_tls_mbedtls_print_error_msg(ret);
        return ESP_ERR_MBEDTLS_CTR_DRBG_SEED_FAILED;
    }

    mbedtls_ssl_set_user_data_p(&sub_tls_handle->ssl, sub_tls_handle);
    mbedtls_ssl_conf_rng(&sub_tls_handle->conf, mbedtls_ctr_drbg_random, &sub_tls_handle->ctr_drbg);

#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&sub_tls_handle->conf, CONFIG_MBEDTLS_DEBUG_LEVEL);
#endif

#ifdef CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
    mbedtls_ssl_conf_min_tls_version(&sub_tls_handle->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&sub_tls_handle->conf, MBEDTLS_SSL_VERSION_TLS1_3);
#endif

    if ((ret = mbedtls_ssl_setup(&sub_tls_handle->ssl, &sub_tls_handle->conf)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%04X", -ret);
        sub_tls_mbedtls_print_error_msg(ret);
        return ESP_ERR_MBEDTLS_SSL_SETUP_FAILED;
    }

    mbedtls_ssl_set_bio(&sub_tls_handle->ssl, sub_tls_handle, mbedtls_over_tcp_trans_send, mbedtls_over_tcp_trans_recv, NULL);
    return ESP_OK;
}

static int sub_tls_connect(esp_transport_handle_t transport, const char *const host, int port, int timeout_ms)
{
    ESP_LOGD(TAG, "SubTLS connecting!");
    transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL || handle->parent == NULL) {
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

    // Now we create our custom magic mbedTLS handle
    esp_err_t ret = sub_tls_create_mbedtls_handle(host, handle, true);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set up mbedTLS! 0x%x", ret);
        return ret;
    }

    ESP_LOGI(TAG, "Inited with handle %p, %p, handshaking", handle, transport);

    while ((ret = mbedtls_ssl_handshake(&handle->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
            return ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED;
        }
    }

    ESP_LOGI(TAG, "Handshake OK, verify x509");

    uint32_t flags = 0;
    if ((flags = mbedtls_ssl_get_verify_result(&handle->ssl)) != 0) {
        /* In real life, we probably want to close connection if ret != 0 */
        ESP_LOGW(TAG, "Failed to verify peer certificate!");
        char buf[512] = { 0 };
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
        ESP_LOGW(TAG, "verification info: %s", buf);
    } else {
        ESP_LOGI(TAG, "Certificate verified, cipher suite is %s", mbedtls_ssl_get_ciphersuite(&handle->ssl));
    }

    return 0;
}

static int sub_tls_close(esp_transport_handle_t transport)
{
    ESP_LOGD(TAG, "SubTLS closing!");
    transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        return -1;
    }

    mbedtls_ssl_close_notify(&handle->ssl);
    int32_t ret = esp_transport_close(handle->parent);
    if (ret < 0) {
        ESP_LOGE(TAG, "Failed to close connection; ret=%ld", ret);
    }

    mbedtls_ssl_free(&handle->ssl);
    return 0;
}

static int sub_tls_write(esp_transport_handle_t transport, const char *buffer, int len, int timeout_ms)
{
    transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        return -1;
    }

    size_t offset = 0;

    do {
        int ret = mbedtls_ssl_write(&handle->ssl, (const unsigned char *)(buffer + offset), (len - offset));
        if (ret >= 0) {
            offset += ret;
            ESP_LOGD(TAG, "Tx %d bytes", ret);
        } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) {
            ESP_LOGE(TAG, "mbedtls_ssl_write() error, errno=%d, %s, ret=0x%x", errno, strerror(errno), ret);
            return -1;
        }
    } while (offset < len);

    return 0;
}

static int sub_tls_read(esp_transport_handle_t transport, char *buffer, int len, int timeout_ms)
{
    ESP_LOGD(TAG, "SubTLS reading!");
    transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        return -1;
    }

    int ret = 0;
    size_t offset = 0;
    mbedtls_ssl_conf_read_timeout(&handle->conf, timeout_ms);
    do {
        ret = mbedtls_ssl_read(&handle->ssl, (unsigned char *)(buffer + offset), (len - offset));
#if CONFIG_MBEDTLS_SSL_PROTO_TLS1_3 && CONFIG_MBEDTLS_CLIENT_SSL_SESSION_TICKETS
        if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
            ESP_LOGD(TAG, "got session ticket in TLS 1.3 connection, retry read");
            continue;
        }
#endif // CONFIG_MBEDTLS_SSL_PROTO_TLS1_3 && CONFIG_MBEDTLS_CLIENT_SSL_SESSION_TICKETS

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            ret = 0;
            break;
        }

        if (ret < 0) {
            ESP_LOGE(TAG, "mbedtls_ssl_read returned 0x%x", ret);
            break;
        }

        if (ret == 0) {
            ESP_LOGW(TAG, "Connection closed??");
            break;
        }
    } while (offset < len);

    return 0;
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
        ESP_LOGE(TAG, "poll_write has null context???");
        return -1;
    }

    return esp_transport_poll_write(handle->parent, handle->cfg.timeout_ms > timeout_ms ? handle->cfg.timeout_ms : timeout_ms);
}

static esp_err_t sub_tls_destroy(esp_transport_handle_t transport)
{
    ESP_LOGW(TAG, "SubTLS Destroying!");
    if (transport == NULL) {
        return ESP_OK;
    }

    transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        return ESP_ERR_INVALID_ARG; // Might have been freed before??
    }

    ESP_LOGW(TAG, "Handle %p gonna be destroyed!", handle);

    mbedtls_ssl_close_notify(&handle->ssl);

    esp_transport_close(handle->parent);

    mbedtls_ssl_free(&handle->ssl);

    if (transport->foundation != NULL && handle->parent->foundation != transport->foundation) {
        esp_transport_destroy_foundation_transport(transport->foundation);
        transport->foundation = NULL;
    }

    free(handle);

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
