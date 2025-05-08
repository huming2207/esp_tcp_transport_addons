#include <esp_log.h>
#include <string.h>
#include <lwip/sockets.h>
#include <esp_transport_tcp.h>
#include <esp_transport_ssl.h>
#include <http_parser.h>
#include <lwip/netdb.h>
#include "esp_transport_http_proxy.h"
#include "esp_transport_internal.h"
#include "esp_transport_sub_tls.h"

static const char *TAG = "trans_http_pxy";
static const size_t MAX_HEADER_LEN = 8192;

#define HTTP_PROXY_KEEP_ALIVE_IDLE       (5)
#define HTTP_PROXY_KEEP_ALIVE_INTERVAL   (5)
#define HTTP_PROXY_KEEP_ALIVE_COUNT      (3)
#define HTTP_PROXY_CONNECT_FIRST_TIMEOUT (1500UL)

static const char *proxy_alpn_cfgs[2] = { "http/1.1", NULL };

typedef struct transport_http_proxy_t {
    uint16_t proxy_port;
    uint16_t last_http_state;
    int32_t redir_retry_cnt;
    esp_transport_handle_t parent;
    char *proxy_host;
    char *user_agent;
    esp_transport_keep_alive_t keep_alive_cfg;
    http_parser header_parser;
    http_parser_settings header_parser_cfg;
    char curr_header_key[32];
} transport_http_proxy_t;

static int get_port(const char *url, struct http_parser_url *u)
{
    if (u->field_data[UF_PORT].len) {
        return strtol(&url[u->field_data[UF_PORT].off], NULL, 10);
    } else {
        if (strncasecmp(&url[u->field_data[UF_SCHEMA].off], "http", u->field_data[UF_SCHEMA].len) == 0) {
            return 80;
        } else if (strncasecmp(&url[u->field_data[UF_SCHEMA].off], "https", u->field_data[UF_SCHEMA].len) == 0) {
            return 443;
        }
    }
    return 0;
}

static int http_on_header_field(http_parser *parser, const char *at, size_t length)
{
    transport_http_proxy_t *handle = parser->data;
    size_t cpy_len = (length > (sizeof(handle->curr_header_key) - 1)) ? (sizeof(handle->curr_header_key) - 1) : length;
    strncpy(handle->curr_header_key, at, cpy_len);
    handle->curr_header_key[sizeof(handle->curr_header_key) - 1] = '\0';
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
            if (handle->proxy_host != NULL) {
                free(handle->proxy_host);
            }

            handle->proxy_host = strndup(&at[url_parse_state.field_data[UF_HOST].off], url_parse_state.field_data[UF_HOST].len);
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

    size_t parsed_len = http_parser_execute(&handle->header_parser, &handle->header_parser_cfg, connect_header, header_len);
    if (parsed_len < 1) {
        ESP_LOGE(TAG, "Failed to parse header!");
        free(connect_header);
        return -1;
    }

    uint32_t status_code = handle->header_parser.status_code;
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
            return ret;
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

    return esp_transport_read(handle->parent, buffer, len, timeout_ms);
}

static int http_proxy_poll_read(esp_transport_handle_t transport, int timeout_ms)
{
    if (transport == NULL) {
        ESP_LOGE(TAG, "Transport context is null at poll_read!");
        return -1;
    }

    transport_http_proxy_t *handle = esp_transport_get_context_data(transport);
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

    transport_http_proxy_t *handle = esp_transport_get_context_data(transport);
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

    if (handle->user_agent != NULL) free(handle->user_agent);
    if (handle->proxy_host != NULL) free(handle->proxy_host);
    if (transport->foundation != NULL && handle->parent->foundation != transport->foundation) {
        esp_transport_destroy_foundation_transport(transport->foundation);
        transport->foundation = NULL;
    }

    free(handle);

    ESP_LOGI(TAG, "Handle %p destroyed OK!", handle);
    return ESP_OK;
}

static int http_proxy_get_sockfd(esp_transport_handle_t transport)
{
    if (transport) {
        transport_http_proxy_t *handle = esp_transport_get_context_data(transport);
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

        esp_err_t ret = esp_transport_set_default_port(proxy_handle->parent, config->proxy_port);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to set SSL port: 0x%x", ret);
            return ret;
        }

        esp_transport_ssl_set_alpn_protocol(proxy_handle->parent, proxy_alpn_cfgs);

        if (config->use_global_ca_store == true) {
            esp_transport_ssl_enable_global_ca_store(proxy_handle->parent);
        } else if (config->cert) {
            if (!config->cert_len) {
                esp_transport_ssl_set_cert_data(proxy_handle->parent, config->cert, (int)strlen(config->cert));
            } else {
                esp_transport_ssl_set_cert_data_der(proxy_handle->parent, config->cert, (int)config->cert_len);
            }
        }

        if (config->client_cert) {
            if (!config->client_cert_len) {
                esp_transport_ssl_set_client_cert_data(proxy_handle->parent, config->client_cert, (int)strlen(config->client_cert));
            } else {
                esp_transport_ssl_set_client_cert_data_der(proxy_handle->parent, config->client_cert, (int)config->client_cert_len);
            }
        }

        if (config->client_key) {
            if (!config->client_key_len) {
                esp_transport_ssl_set_client_key_data(proxy_handle->parent, config->client_key, (int)strlen(config->client_key));
            } else {
                esp_transport_ssl_set_client_key_data_der(proxy_handle->parent, config->client_key, (int)config->client_key_len);
            }
        }

        if (config->crt_bundle_attach) {
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
            esp_transport_ssl_crt_bundle_attach(proxy_handle->parent, config->crt_bundle_attach);
#else //CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
            ESP_LOGE(TAG, "crt_bundle_attach configured but not enabled in menuconfig: Please enable MBEDTLS_CERTIFICATE_BUNDLE option");
#endif
        }

        if (config->skip_cert_common_name_check) {
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

    if (config->parent_handle != NULL) {
        esp_err_t ret = http_proxy_init_with_parent(transport, config);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to prepare parent handle: 0x%x", ret);
            return ret;
        }
    } else {
        esp_err_t ret = http_proxy_init_standalone(transport, config);
        if (ret != ESP_OK) {
            return ret;
        }
    }

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

esp_err_t esp_transport_create_proxied_plain_tcp(esp_transport_handle_t *new_proxied_handle, const esp_transport_http_proxy_config_t *config)
{
    // Do we need to do anything else??
    return esp_transport_http_proxy_init(new_proxied_handle, config);
}

esp_err_t esp_transport_create_proxied_tls(esp_transport_handle_t *new_subtls_pxy_handle, esp_transport_handle_t *new_http_pxy_handle, const esp_transport_http_proxy_config_t *proxy_config, const esp_transport_sub_tls_config_t *tls_config)
{
    if (new_subtls_pxy_handle == NULL || proxy_config == NULL || tls_config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_transport_handle_t http_proxy_handle = NULL;
    esp_err_t ret = esp_transport_http_proxy_init(&http_proxy_handle, proxy_config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Proxy init failed: 0x%x", ret);
        return ret;
    }

    esp_transport_handle_t tls_handle = NULL;
    ret = esp_transport_sub_tls_init(&tls_handle, http_proxy_handle, tls_config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "TLS init failed: 0x%x", ret);
        return ret;
    }

    *new_subtls_pxy_handle = tls_handle;
    *new_http_pxy_handle = http_proxy_handle;
    return ret;
}
