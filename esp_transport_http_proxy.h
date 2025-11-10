#pragma once

#include <esp_transport.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct esp_transport_http_proxy_tls_config {
    bool use_global_ca_store;
    bool skip_cert_common_name_check;
    const char *cert;
    size_t cert_len;
    const char *client_cert;
    size_t client_cert_len;
    const char *client_key;
    size_t client_key_len;
    esp_err_t (*crt_bundle_attach)(void *conf);
} esp_transport_http_proxy_tls_config_t;

/**
 * Configuration struct
 */
typedef struct esp_transport_http_proxy_config_t {
    bool is_https_proxy; // True if you want an HTTPS proxy
    bool tunnel_has_tls; // True if you want to create a TLS tunnel, false to create a plain TCP tunnel
    bool disable_keep_alive;
    int timeout_ms;
    uint16_t proxy_port;
    const char *proxy_host;
    const char *user_agent;
    int32_t redir_retry_cnt;
    esp_transport_handle_t parent_handle;           /*!< Specify a parent handle here to let this HTTP proxy to run on it - or keep it null to create a new one by its own */
    struct ifreq *if_name;
    int keep_alive_idle;                            /*!< Keep-alive idle time. Default is 5 (second) */
    int keep_alive_interval;                        /*!< Keep-alive interval time. Default is 5 (second) */
    int keep_alive_count;                           /*!< Keep-alive packet retry send count. Default is 3 counts */
    esp_transport_http_proxy_tls_config_t server_tls; // Proxy server's TLS config
    esp_transport_http_proxy_tls_config_t tunnel_tls; // Tunnel's sub-TLS (the one within the proxy session)
} esp_transport_http_proxy_config_t;

esp_err_t esp_transport_http_proxy_init(esp_transport_handle_t *new_proxy_handle, const esp_transport_http_proxy_config_t *config);

#ifdef __cplusplus
}
#endif //__cplusplus