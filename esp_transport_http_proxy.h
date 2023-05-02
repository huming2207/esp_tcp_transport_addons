#pragma once

#include <esp_transport.h>

/**
 * Configuration struct
 */
typedef struct esp_transport_http_proxy_config_t {
    uint16_t proxy_port;
    uint32_t alloc_cap_flag;
    const char *proxy_host;
    const char *user_agent;
} esp_transport_http_proxy_config_t;

esp_transport_handle_t esp_transport_http_proxy_init(esp_transport_handle_t parent_handle, const esp_transport_http_proxy_config_t *config);