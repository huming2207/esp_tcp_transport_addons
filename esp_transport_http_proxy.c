#include <esp_log.h>
#include <esp_heap_caps.h>
#include "esp_transport_http_proxy.h"

static const char *TAG = "trans_http_pxy";

typedef struct transport_http_proxy_t {
    uint16_t port;
    esp_transport_handle_t parent;
    char *host;
    char *username;
    char *password;
} transport_http_proxy_t;

static int http_proxy_connect(esp_transport_handle_t transport, const char *const host, int port, int timeout_ms)
{
    if (transport == NULL) {
        ESP_LOGE(TAG, "Transport context is null at connect!");
        return -1;
    }

    return 0;
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

    if (handle == NULL) {
        return ESP_OK; // Might have been freed before??
    }

    // TODO: free stuff here

    return ESP_OK;

}

esp_transport_handle_t esp_transport_http_proxy_init(esp_transport_handle_t parent_handle, const esp_transport_http_proxy_config_t *config)
{
    if (parent_handle == NULL || config == NULL) {
        return NULL;
    }

    esp_transport_handle_t transport = esp_transport_init();
    if (transport == NULL) {
        ESP_LOGE(TAG, "Failed to create transport handle");
        return NULL;
    }

    transport_http_proxy_t *proxy_handle = calloc(1, sizeof(transport_http_proxy_t));
    if (proxy_handle == NULL) {
        esp_transport_destroy(transport);
        return NULL;
    }

    proxy_handle->parent = parent_handle;
    proxy_handle->port = config->port;

    esp_transport_set_func(transport, http_proxy_connect, http_proxy_read, http_proxy_write, http_proxy_close, http_proxy_poll_read, http_proxy_poll_write, http_proxy_destroy);
    esp_transport_set_context_data(transport, proxy_handle);

    return transport;
}
