#include <esp_log.h>
#include <string.h>
#include <lwip/sockets.h>
#include <esp_transport_tcp.h>
#include <esp_transport_ssl.h>
#include <http_parser.h>
#include <lwip/netdb.h>
#include "esp_transport_http_proxy.h"
#include "esp_transport_internal.h"
#include <esp_tls_mbedtls.h>
#include <esp_crt_bundle.h>
#include <sys/param.h>

static const char *TAG = "trans_http_pxy";
static const size_t MAX_HEADER_LEN = 8192;

#define HTTP_PROXY_KEEP_ALIVE_IDLE       (5)
#define HTTP_PROXY_KEEP_ALIVE_INTERVAL   (5)
#define HTTP_PROXY_KEEP_ALIVE_COUNT      (3)
#define HTTP_PROXY_CONNECT_FIRST_TIMEOUT (1500UL)

static const char *proxy_alpn_cfgs[2] = { "http/1.1", NULL };

typedef struct transport_http_proxy_t {
    bool tunnel_use_tls;
    uint16_t proxy_port;
    uint16_t last_http_state;
    uint32_t timeout_ms;
    int32_t redir_retry_cnt;
    esp_transport_handle_t parent;
    char *proxy_host;
    char *user_agent;
    bool parent_is_owned;
    esp_transport_keep_alive_t keep_alive_cfg;
    http_parser header_parser;
    http_parser_settings header_parser_cfg;
    char curr_header_key[32];
    struct {
        mbedtls_ssl_context ssl;                                                    /*!< TLS/SSL context */
        mbedtls_entropy_context entropy;                                            /*!< mbedTLS entropy context structure */
        mbedtls_ctr_drbg_context ctr_drbg;                                          /*!< mbedTLS ctr drbg context structure.
                                                                                         CTR_DRBG is deterministic random
                                                                                         bit generation based on AES-256 */
        mbedtls_ssl_config conf;                                                    /*!< TLS/SSL configuration to be shared
                                                                                         between mbedtls_ssl_context
                                                                                         structures */
        mbedtls_x509_crt cacert;
        esp_transport_http_proxy_tls_config_t tls_cfg;
    } tls;
} transport_http_proxy_t;

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

/* This function shall return the error message when appropriate log level has been set, otherwise this function shall do nothing */
static void sub_tls_mbedtls_print_error_msg(int error)
{
#if (CONFIG_LOG_DEFAULT_LEVEL_DEBUG || CONFIG_LOG_DEFAULT_LEVEL_VERBOSE)
    static char error_buf[100];
    mbedtls_strerror(error, error_buf, sizeof(error_buf));
    ESP_LOGI(TAG, "(%04X): %s", error, error_buf);
#endif
}

// Remember the ctx here is transport_sub_tls_t!!
static int mbedtls_over_tcp_trans_recv(void *ctx, unsigned char *buf, size_t len)
{
    if (ctx == NULL) {
        ESP_LOGE(TAG, "Context is null");
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }


    const transport_http_proxy_t *handle = ctx;
    ESP_LOGD(TAG, "Recv: ctx %p, buf %p, len %d", ctx, buf, len);

    int ret = esp_transport_read(handle->parent, (char *)buf, (int)len, handle->timeout_ms);

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

    const transport_http_proxy_t *handle = ctx;
    ESP_LOGD(TAG, "Send: ctx %p, parent %p, buf %p, len %d", ctx, handle->parent, buf, len);

    int ret = esp_transport_write(handle->parent, (const char *)buf, (int)len, handle->timeout_ms);

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

static esp_err_t sub_tls_create_mbedtls_handle(const char *hostname, transport_http_proxy_t *proxy_handle, bool use_esp_crt_bundle)
{
    if (proxy_handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!use_esp_crt_bundle) {
        ESP_LOGE(TAG, "Custom certification bundle is not yet supported");
        return ESP_ERR_NOT_SUPPORTED;
    }

    int ret;
    esp_err_t esp_ret = ESP_OK;

#ifdef CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
    const psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to initialize PSA crypto, returned %d\n", (int) status);
        return ESP_FAIL;
    }
#endif // CONFIG_MBEDTLS_SSL_PROTO_TLS1_3

    mbedtls_ssl_init(&proxy_handle->tls.ssl);
    mbedtls_x509_crt_init(&proxy_handle->tls.cacert);
    mbedtls_ctr_drbg_init(&proxy_handle->tls.ctr_drbg);
    mbedtls_ssl_config_init(&proxy_handle->tls.conf);
    mbedtls_entropy_init(&proxy_handle->tls.entropy);

    if (use_esp_crt_bundle) {
        ESP_LOGD(TAG, "Setting up cert bundle");
        ret = esp_crt_bundle_attach(&proxy_handle->tls.conf);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to attach crt bundle! 0x%x", ret);
            esp_ret = ret;
            goto mbedtls_err_cleanup;
        }
    }

    ESP_LOGI(TAG, "Setting hostname %s", hostname);
    ret = mbedtls_ssl_set_hostname(&proxy_handle->tls.ssl, hostname);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname failed: -0x%x", ret);
        esp_ret = ESP_FAIL;
        goto mbedtls_err_cleanup;
    }

    if((ret = mbedtls_ssl_config_defaults(&proxy_handle->tls.conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        esp_ret = ESP_FAIL;
        goto mbedtls_err_cleanup;
    }

    mbedtls_ssl_conf_authmode(&proxy_handle->tls.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&proxy_handle->tls.conf, &proxy_handle->tls.cacert, NULL);
    mbedtls_ssl_conf_rng(&proxy_handle->tls.conf, mbedtls_ctr_drbg_random, &proxy_handle->tls.ctr_drbg);
#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&proxy_handle->tls.conf, CONFIG_MBEDTLS_DEBUG_LEVEL);
#endif

    if ((ret = mbedtls_ctr_drbg_seed(&proxy_handle->tls.ctr_drbg, mbedtls_entropy_func, &proxy_handle->tls.entropy, NULL, 0)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned -0x%04X", -ret);
        sub_tls_mbedtls_print_error_msg(ret);
        esp_ret = ESP_ERR_MBEDTLS_CTR_DRBG_SEED_FAILED;
        goto mbedtls_err_cleanup;
    }

    mbedtls_ssl_set_user_data_p(&proxy_handle->tls.ssl, proxy_handle);
    mbedtls_ssl_conf_rng(&proxy_handle->tls.conf, mbedtls_ctr_drbg_random, &proxy_handle->tls.ctr_drbg);

#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&proxy_handle->tls.conf, CONFIG_MBEDTLS_DEBUG_LEVEL);
#endif

#ifdef CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
    mbedtls_ssl_conf_max_tls_version(&proxy_handle->tls.conf, MBEDTLS_SSL_VERSION_TLS1_3);
#endif

    if ((ret = mbedtls_ssl_setup(&proxy_handle->tls.ssl, &proxy_handle->tls.conf)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%04X", -ret);
        sub_tls_mbedtls_print_error_msg(ret);
        esp_ret = ESP_ERR_MBEDTLS_SSL_SETUP_FAILED;
        goto mbedtls_err_cleanup;
    }

    mbedtls_ssl_set_bio(&proxy_handle->tls.ssl, proxy_handle, mbedtls_over_tcp_trans_send, mbedtls_over_tcp_trans_recv, NULL);
    return ESP_OK;

mbedtls_err_cleanup:
    mbedtls_x509_crt_free(&proxy_handle->tls.cacert);
    mbedtls_entropy_free(&proxy_handle->tls.entropy);
    mbedtls_ssl_config_free(&proxy_handle->tls.conf);
    mbedtls_ctr_drbg_free(&proxy_handle->tls.ctr_drbg);
    mbedtls_ssl_free(&proxy_handle->tls.ssl);
    return esp_ret;
}


static int get_port(const char *url, struct http_parser_url *u)
{
    if (u->field_data[UF_PORT].len) {
        return strtol(&url[u->field_data[UF_PORT].off], NULL, 10);
    }

    if (strncasecmp(&url[u->field_data[UF_SCHEMA].off], "http", u->field_data[UF_SCHEMA].len) == 0) {
        return 80;
    }

    if (strncasecmp(&url[u->field_data[UF_SCHEMA].off], "https", u->field_data[UF_SCHEMA].len) == 0) {
        return 443;
    }

    return 0;
}

static int http_on_header_field(http_parser *parser, const char *at, size_t length)
{
    transport_http_proxy_t *handle = parser->data;
    const size_t cpy_len = (length > (sizeof(handle->curr_header_key) - 1)) ? (sizeof(handle->curr_header_key) - 1) : length;
    strncpy(handle->curr_header_key, at, cpy_len);
    handle->curr_header_key[MIN(sizeof(handle->curr_header_key) - 1, cpy_len)] = '\0';
    ESP_LOGD(TAG, "Got header: %s, len %d", handle->curr_header_key, cpy_len);
    return 0; // Unused
}

static int http_on_header_value(http_parser *parser, const char *at, size_t length)
{
    transport_http_proxy_t *handle = parser->data;
    if (strncasecmp(handle->curr_header_key, "location", (sizeof(handle->curr_header_key) - 1)) == 0) {
        struct http_parser_url url_parse_state = {};
        http_parser_url_init(&url_parse_state);
        if (http_parser_parse_url(at, length, 0, &url_parse_state) == 0) {
            char *new_proxy_host = strndup(&at[url_parse_state.field_data[UF_HOST].off], url_parse_state.field_data[UF_HOST].len);
            if (new_proxy_host == NULL) {
                ESP_LOGE(TAG, "Failed to allocate memory for new proxy host from redirection");
                return -1;
            }

            if (handle->proxy_host != NULL) {
                free(handle->proxy_host);
            }

            handle->proxy_host = new_proxy_host;
            handle->proxy_port = get_port(at, &url_parse_state);
        } else {
            ESP_LOGW(TAG, "Location header found but failed to parse URL:");
            ESP_LOG_BUFFER_CHAR_LEVEL(TAG, at, length, ESP_LOG_WARN);
        }
    }

    return 0;
}

static int http_proxy_connect_follow_redirect(transport_http_proxy_t *handle, const char *const host, int port, int timeout_ms)
{
    if (host == NULL) {
        ESP_LOGW(TAG, "follow_redirect: no host provided, skip");
        return 0;
    }

    ESP_LOGI(TAG, "follow_redirect: following to %s : %d", host, port);
    char *connect_header = calloc(MAX_HEADER_LEN, sizeof(char));
    if (connect_header == NULL) {
        ESP_LOGE(TAG, "Failed to allocate header buffer");
        return -2;
    }

    // In some cases, the TCP socket connect() will always fail upon the very first connection. Here we do a quick attempt and fail early.
    // If it fails, then do another one right after.
    ESP_LOGI(TAG, "Connecting to proxy host: %s at port %u, timeout %lu ms", handle->proxy_host, handle->proxy_port, HTTP_PROXY_CONNECT_FIRST_TIMEOUT);
    int connect_ret = esp_transport_connect(handle->parent, handle->proxy_host, handle->proxy_port, HTTP_PROXY_CONNECT_FIRST_TIMEOUT);

    if (connect_ret < 0) {
        ESP_LOGI(TAG, "2nd attempt: Connecting to proxy host: %s at port %u, timeout %d ms", handle->proxy_host, handle->proxy_port, timeout_ms);
        connect_ret = esp_transport_connect(handle->parent, handle->proxy_host, handle->proxy_port, timeout_ms);
        if (connect_ret < 0) {
            ESP_LOGE(TAG, "Parent transport method connect fail: %d", connect_ret);
            free(connect_header);
            return connect_ret;
        }
    }

    ESP_LOGI(TAG, "Connecting to host via proxy: %s:%d", host, port);
    snprintf(connect_header, MAX_HEADER_LEN, "CONNECT %s:%d HTTP/1.1\r\n"
                                             "Host: %s\r\n"
                                             "User-Agent: %s\r\n"
                                             "Proxy-Connection: Keep-Alive\r\n"
                                             "\r\n",
             host, port, host, handle->user_agent == NULL ? "ESP-IDF/1.0" : handle->user_agent);

    // Perform the CONNECT
    size_t connect_header_len = strnlen(connect_header, MAX_HEADER_LEN);
    int rw_ret = esp_transport_write(handle->parent, connect_header, (int)connect_header_len, timeout_ms);
    if (rw_ret < 0) {
        ESP_LOGE(TAG, "CONNECT write failed: %s", strerror(errno));
        free(connect_header);
        return rw_ret;
    }

    memset(connect_header, 0, MAX_HEADER_LEN);

    size_t header_len = 0;
    do {
        if ((rw_ret = esp_transport_read(handle->parent, connect_header + header_len, (int)(MAX_HEADER_LEN - header_len), timeout_ms)) <= 0) {
            ESP_LOGE(TAG, "CONNECT response read failed: %s", strerror(errno));
            free(connect_header);
            return rw_ret;
        }

        header_len += rw_ret;
        connect_header[header_len] = '\0';
    } while (strstr(connect_header, "\r\n\r\n") == NULL && header_len < (MAX_HEADER_LEN - 1));

    const size_t parsed_len = http_parser_execute(&handle->header_parser, &handle->header_parser_cfg, connect_header, header_len);
    if (parsed_len < 1) {
        ESP_LOGE(TAG, "Failed to parse header!");
        free(connect_header);
        return -1;
    }

    const uint32_t status_code = handle->header_parser.status_code;
    handle->last_http_state = status_code;

    if (status_code >= 300 && status_code <= 399) {
        ESP_LOGW(TAG, "Redirection found: %lu; new location: %s port %u", status_code, handle->proxy_host, handle->proxy_port);
        free(connect_header);
        return 0;
    }

    if (status_code != 200) {
        ESP_LOGE(TAG, "CONNECT responded with failed status code: %lu\n===\nHeader\n===\n%s\n======", status_code, connect_header);
        free(connect_header);
        return -1;
    }

    free(connect_header);
    return 0;
}

static int http_proxy_connect(esp_transport_handle_t transport, const char *const host, int port, int timeout_ms)
{
    ESP_LOGD(TAG, "http_proxy_connect: begin");
    if (transport == NULL) {
        ESP_LOGE(TAG, "Transport context is null at connect!");
        return -1;
    }

    transport_http_proxy_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        ESP_LOGE(TAG, "Internal context is null at connect!");
        return -1;
    }

    int ret = http_proxy_connect_follow_redirect(handle, host, port, timeout_ms);
    if (ret != 0) {
        return ret;
    }

    int32_t redir_cnt = handle->redir_retry_cnt;
    while (handle->last_http_state >= 300 && handle->last_http_state <= 399 && redir_cnt >= 0) {
        ret = http_proxy_connect_follow_redirect(handle, host, port, timeout_ms);
        redir_cnt -= 1;
        if (ret != 0) {
            ESP_LOGE(TAG, "Too many redirect, reject now!");
            return ret;
        }
    }

    ESP_LOGI(TAG, "HTTP server returned %u", handle->last_http_state);
    if (handle->tunnel_use_tls) {
        ESP_LOGI(TAG, "TLS enabled for HTTP proxy %p", transport);
        const esp_err_t esp_ret = sub_tls_create_mbedtls_handle(host, handle, handle->tls.tls_cfg.use_global_ca_store);
        if (esp_ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to set up mbedTLS! 0x%x", esp_ret);
            return -1;
        }

        ESP_LOGI(TAG, "tls: inited: %p %p; handshaking", handle, transport);

        while ((ret = mbedtls_ssl_handshake(&handle->tls.ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
                return ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED;
            }
        }

        ESP_LOGI(TAG, "tls: Handshake OK, verify x509");

        uint32_t flags = 0;
        if ((flags = mbedtls_ssl_get_verify_result(&handle->tls.ssl)) != 0) {
            /* In real life, we probably want to close connection if ret != 0 */
            ESP_LOGW(TAG, "tls: Failed to verify peer certificate!");
            char buf[512] = { 0 };
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
            ESP_LOGW(TAG, "tls: verification info: %s", buf);
        } else {
            ESP_LOGI(TAG, "tls: Certificate verified, cipher suite is %s", mbedtls_ssl_get_ciphersuite(&handle->tls.ssl));
        }
    }

    return ret;
}

static int http_proxy_close(esp_transport_handle_t transport)
{
    if (transport == NULL) {
        ESP_LOGE(TAG, "Transport context is null at close!");
        return -1;
    }

    transport_http_proxy_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        ESP_LOGE(TAG, "Internal context is null at close!");
        return -1;
    }

    if (handle->tunnel_use_tls) {
        ESP_LOGI(TAG, "close: cleaning up TLS");
        mbedtls_ssl_close_notify(&handle->tls.ssl);
        mbedtls_x509_crt_free(&handle->tls.cacert);
        mbedtls_entropy_free(&handle->tls.entropy);
        mbedtls_ssl_config_free(&handle->tls.conf);
        mbedtls_ctr_drbg_free(&handle->tls.ctr_drbg);
        mbedtls_ssl_free(&handle->tls.ssl);
        ESP_LOGI(TAG, "close: TLS cleared");
    }

    return esp_transport_close(handle->parent);
}

static int http_proxy_write(esp_transport_handle_t transport, const char *buffer, int len, int timeout_ms)
{
    if (transport == NULL) {
        ESP_LOGE(TAG, "Transport context is null at write!");
        return -1;
    }

    transport_http_proxy_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        ESP_LOGE(TAG, "Internal context is null at write!");
        return -1;
    }

    if (handle->tunnel_use_tls) {
        size_t offset = 0;
        do {
            const int ret = mbedtls_ssl_write(&handle->tls.ssl, (const unsigned char *)(buffer + offset), (len - offset));
            if (ret >= 0) {
                offset += ret;
                ESP_LOGD(TAG, "Tx %d bytes", ret);
            } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) {
                ESP_LOGE(TAG, "mbedtls_ssl_write() error, errno=%d, %s, ret=0x%x %d", errno, strerror(errno), ret, ret);
                return -1;
            }
        } while (offset < len);

        return offset;
    }

    return esp_transport_write(handle->parent, buffer, len, timeout_ms);
}

static int http_proxy_read(esp_transport_handle_t transport, char *buffer, int len, int timeout_ms)
{
    if (transport == NULL) {
        ESP_LOGE(TAG, "Transport context is null at read!");
        return -1;
    }

    transport_http_proxy_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        ESP_LOGE(TAG, "Internal context is null at read!");
        return -1;
    }

    if (handle->tunnel_use_tls) {
        int ret = 0;
        mbedtls_ssl_conf_read_timeout(&handle->tls.conf, timeout_ms);
        do {
            ret = mbedtls_ssl_read(&handle->tls.ssl, (unsigned char *)buffer, len);
#if CONFIG_MBEDTLS_SSL_PROTO_TLS1_3 && CONFIG_MBEDTLS_CLIENT_SSL_SESSION_TICKETS
            if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
                ESP_LOGD(TAG, "tls@read: got session ticket in TLS 1.3 connection, retry read");
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
                ESP_LOGE(TAG, "tls@read: mbedtls_ssl_read returned 0x%x", ret);
                break;
            }

            if (ret == 0) {
                ESP_LOGW(TAG, "tls@read: Connection closed??");
                break;
            } else {
                return ret;
            }
        } while (true);

        return ret;
    }

    return esp_transport_read(handle->parent, buffer, len, timeout_ms);
}

static int http_proxy_poll_read(esp_transport_handle_t transport, int timeout_ms)
{
    if (transport == NULL) {
        ESP_LOGE(TAG, "Transport context is null at poll_read!");
        return -1;
    }

    const transport_http_proxy_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        ESP_LOGE(TAG, "Internal context is null at poll_read!");
        return -1;
    }

    return esp_transport_poll_read(handle->parent, timeout_ms);
}

static int http_proxy_poll_write(esp_transport_handle_t transport, int timeout_ms)
{
    if (transport == NULL) {
        ESP_LOGE(TAG, "Transport context is null at poll_write!");
        return -1;
    }

    const transport_http_proxy_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        ESP_LOGE(TAG, "Internal context is null at poll_write!");
        return -1;
    }

    return esp_transport_poll_write(handle->parent, timeout_ms);
}

static esp_err_t http_proxy_destroy(esp_transport_handle_t transport)
{
    if (transport == NULL) {
        return ESP_OK;
    }

    transport_http_proxy_t *handle = esp_transport_get_context_data(transport);
    ESP_LOGI(TAG, "Handle %p gonna be destroyed!", handle);
    if (handle == NULL) {
        return ESP_ERR_INVALID_ARG; // Might have been freed before??
    }

    esp_transport_close(transport);

    if (handle->user_agent != NULL) free(handle->user_agent);
    if (handle->proxy_host != NULL) free(handle->proxy_host);

    if (handle->parent_is_owned) {
        ESP_LOGI(TAG, "Freeing own parent transport %p", handle->parent);
        esp_transport_destroy(handle->parent); // Also frees the foundation
    } else {
        if (transport->foundation != NULL && handle->parent->foundation != transport->foundation) {
            esp_transport_destroy_foundation_transport(transport->foundation);
            transport->foundation = NULL;
        }
    }

    free(handle);
    return ESP_OK;
}

static int http_proxy_get_sockfd(esp_transport_handle_t transport)
{
    if (transport) {
        const transport_http_proxy_t *handle = esp_transport_get_context_data(transport);
        if (handle && handle->parent && handle->parent->_get_socket) {
            return handle->parent->_get_socket(handle->parent);
        }
    }

    return -1;
}

static esp_err_t http_proxy_init_with_parent(esp_transport_handle_t transport, const esp_transport_http_proxy_config_t *config)
{
    if (config == NULL || transport == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (config->parent_handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    // I know this is shit, but I have no choice...
    // Upstream tcp-transport doesn't expose the foundation pointer, so I have to have some dirty hacks here...
    // This has to be here, otherwise transport_ws won't work with this HTTP proxy handle
    if (config->parent_handle->foundation == NULL) {
        transport->foundation = config->parent_handle->foundation;
    } else {
        transport->foundation = esp_transport_init_foundation_transport(); // Might be just a placeholder
    }

    transport_http_proxy_t *proxy_handle = (transport_http_proxy_t *)esp_transport_get_context_data(transport);
    proxy_handle->parent = config->parent_handle;

    return ESP_OK;
}

static esp_err_t http_proxy_init_standalone(esp_transport_handle_t transport, const esp_transport_http_proxy_config_t *config)
{
    if (config == NULL || transport == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (config->parent_handle != NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    transport_http_proxy_t *proxy_handle = (transport_http_proxy_t *)esp_transport_get_context_data(transport);

    proxy_handle->redir_retry_cnt = config->redir_retry_cnt;
    if (config->disable_keep_alive) {
        proxy_handle->keep_alive_cfg.keep_alive_enable = false;
    } else {
        proxy_handle->keep_alive_cfg.keep_alive_enable = true;
        proxy_handle->keep_alive_cfg.keep_alive_interval = (config->keep_alive_interval == 0) ? HTTP_PROXY_KEEP_ALIVE_INTERVAL : config->keep_alive_interval;
        proxy_handle->keep_alive_cfg.keep_alive_idle = (config->keep_alive_idle == 0) ? HTTP_PROXY_KEEP_ALIVE_IDLE : config->keep_alive_idle;
        proxy_handle->keep_alive_cfg.keep_alive_count = (config->keep_alive_count == 0) ? HTTP_PROXY_KEEP_ALIVE_COUNT : config->keep_alive_count;
    }

    if (!config->is_https_proxy) {
        proxy_handle->parent = esp_transport_tcp_init();
        if (proxy_handle->parent == NULL) {
            ESP_LOGE(TAG, "Failed to create plain TCP context");
            return ESP_ERR_NO_MEM;
        }

        esp_err_t ret = esp_transport_set_default_port(proxy_handle->parent, config->proxy_port);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to set TCP port: 0x%x", ret);
            return ret;
        }
        esp_transport_tcp_set_keep_alive(proxy_handle->parent, &proxy_handle->keep_alive_cfg);
        esp_transport_tcp_set_interface_name(proxy_handle->parent, config->if_name);
    } else {
        proxy_handle->parent = esp_transport_ssl_init();
        if (proxy_handle->parent == NULL) {
            ESP_LOGE(TAG, "Failed to create SSL context");
            return ESP_ERR_NO_MEM;
        }

        const esp_err_t ret = esp_transport_set_default_port(proxy_handle->parent, config->proxy_port);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to set SSL port: 0x%x", ret);
            return ret;
        }

        esp_transport_ssl_set_alpn_protocol(proxy_handle->parent, proxy_alpn_cfgs);

        if (config->server_tls.use_global_ca_store == true) {
            esp_transport_ssl_enable_global_ca_store(proxy_handle->parent);
        } else if (config->server_tls.cert) {
            if (!config->server_tls.cert_len) {
                esp_transport_ssl_set_cert_data(proxy_handle->parent, config->server_tls.cert, (int)strlen(config->server_tls.cert));
            } else {
                esp_transport_ssl_set_cert_data_der(proxy_handle->parent, config->server_tls.cert, (int)config->server_tls.cert_len);
            }
        }

        if (config->server_tls.client_cert) {
            if (!config->server_tls.client_cert_len) {
                esp_transport_ssl_set_client_cert_data(proxy_handle->parent, config->server_tls.client_cert, (int)strlen(config->server_tls.client_cert));
            } else {
                esp_transport_ssl_set_client_cert_data_der(proxy_handle->parent, config->server_tls.client_cert, (int)config->server_tls.client_cert_len);
            }
        }

        if (config->server_tls.client_key) {
            if (!config->server_tls.client_key_len) {
                esp_transport_ssl_set_client_key_data(proxy_handle->parent, config->server_tls.client_key, (int)strlen(config->server_tls.client_key));
            } else {
                esp_transport_ssl_set_client_key_data_der(proxy_handle->parent, config->server_tls.client_key, (int)config->server_tls.client_key_len);
            }
        }

        if (config->server_tls.crt_bundle_attach) {
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
            esp_transport_ssl_crt_bundle_attach(proxy_handle->parent, config->server_tls.crt_bundle_attach);
#else //CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
            ESP_LOGE(TAG, "crt_bundle_attach configured but not enabled in menuconfig: Please enable MBEDTLS_CERTIFICATE_BUNDLE option");
#endif
        }

        if (config->server_tls.skip_cert_common_name_check) {
            esp_transport_ssl_skip_common_name_check(proxy_handle->parent);
        }

        esp_transport_ssl_set_keep_alive(proxy_handle->parent, &proxy_handle->keep_alive_cfg);
        esp_transport_ssl_set_interface_name(proxy_handle->parent, config->if_name);
    }

    if (proxy_handle->parent->foundation != NULL) {
        transport->foundation = proxy_handle->parent->foundation;
    } else {
        transport->foundation = esp_transport_init_foundation_transport(); // Might be just a placeholder
    }

    return ESP_OK;
}

esp_err_t esp_transport_http_proxy_init(esp_transport_handle_t *new_proxy_handle, const esp_transport_http_proxy_config_t *config)
{
    if (config == NULL || new_proxy_handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_transport_handle_t transport = esp_transport_init();
    if (transport == NULL) {
        ESP_LOGE(TAG, "Failed to create transport handle");
        return ESP_FAIL;
    }

    transport_http_proxy_t *proxy_handle = calloc(1, sizeof(transport_http_proxy_t));
    if (proxy_handle == NULL) {
        ESP_LOGE(TAG, "Failed to allocate proxy handle");
        esp_transport_destroy(transport);
        return ESP_ERR_NO_MEM;
    } else {
        esp_transport_set_context_data(transport, proxy_handle);
    }

    http_parser_init(&proxy_handle->header_parser, HTTP_RESPONSE);
    http_parser_settings_init(&proxy_handle->header_parser_cfg);
    proxy_handle->header_parser_cfg.on_header_field = http_on_header_field;
    proxy_handle->header_parser_cfg.on_header_value = http_on_header_value;
    proxy_handle->header_parser.data = proxy_handle;

    proxy_handle->parent_is_owned = config->parent_handle == NULL; // True if we create the parent transport

    if (config->parent_handle != NULL) {
        ESP_LOGI(TAG, "Using provided parent transport %p", config->parent_handle);
        esp_err_t ret = http_proxy_init_with_parent(transport, config);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to prepare parent handle: 0x%x", ret);
            esp_transport_destroy(transport);
            return ret;
        }
    } else {
        ESP_LOGI(TAG, "Creating our own parent transport");
        esp_err_t ret = http_proxy_init_standalone(transport, config);
        if (ret != ESP_OK) {
            esp_transport_destroy(transport);
            return ret;
        }
    }

    proxy_handle->timeout_ms = config->timeout_ms == 0 ? 10000 : config->timeout_ms; // Default 10 seconds if timeout is 0
    proxy_handle->tunnel_use_tls = config->tunnel_has_tls;
    memcpy(&proxy_handle->tls.tls_cfg, &config->tunnel_tls, sizeof(esp_transport_http_proxy_tls_config_t));
    proxy_handle->proxy_port = config->proxy_port;
    proxy_handle->proxy_host = strdup(config->proxy_host);
    if (proxy_handle->proxy_host == NULL) {
        ESP_LOGE(TAG, "Failed to allocate proxy host string");
        esp_transport_destroy(transport);
        return ESP_ERR_NO_MEM;
    }

    if (config->user_agent != NULL) {
        proxy_handle->user_agent = strdup(config->user_agent);
        if (proxy_handle->user_agent == NULL) {
            ESP_LOGE(TAG, "Failed to allocate proxy user-agent string");
            esp_transport_destroy(transport);
            return ESP_ERR_NO_MEM;
        }
    }

    esp_transport_set_func(transport, http_proxy_connect, http_proxy_read, http_proxy_write, http_proxy_close, http_proxy_poll_read, http_proxy_poll_write, http_proxy_destroy);
    transport->_get_socket = http_proxy_get_sockfd;
    *new_proxy_handle = transport;

    ESP_LOGW(TAG, "Inited with handle %p, %p", proxy_handle, transport);
    return ESP_OK;
}
