#pragma once

#include <esp_transport.h>
#include "esp_transport_sub_tls.h"

/**
 * Configuration struct
 */
typedef struct esp_transport_http_proxy_config_t {
    uint16_t proxy_port;
    const char *proxy_host;
    const char *user_agent;
    bool is_https_proxy;
    esp_transport_handle_t parent_handle;           /*!< Specify a parent handle here to let this HTTP proxy to run on it - or keep it null to create a new one by its own */
    struct ifreq *if_name;
    bool disable_keep_alive;
    int keep_alive_idle;                            /*!< Keep-alive idle time. Default is 5 (second) */
    int keep_alive_interval;                        /*!< Keep-alive interval time. Default is 5 (second) */
    int keep_alive_count;                           /*!< Keep-alive packet retry send count. Default is 3 counts */
    bool use_global_ca_store;
    const char *cert;
    size_t cert_len;
    const char *client_cert;
    size_t client_cert_len;
    const char *client_key;
    size_t client_key_len;
    bool skip_cert_common_name_check;
    esp_err_t (*crt_bundle_attach)(void *conf);
} esp_transport_http_proxy_config_t;

esp_err_t esp_transport_http_proxy_init(esp_transport_handle_t *new_proxy_handle, const esp_transport_http_proxy_config_t *config);
esp_err_t esp_transport_create_proxied_plain_tcp(esp_transport_handle_t *new_proxied_handle, const esp_transport_http_proxy_config_t *config);
esp_err_t esp_transport_create_proxied_tls(esp_transport_handle_t *new_proxied_handle,
                                           const esp_transport_http_proxy_config_t *proxy_config, const esp_transport_sub_tls_config_t *tls_config);