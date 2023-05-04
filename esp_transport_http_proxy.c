#include <esp_log.h>
#include <esp_heap_caps.h>
#include <string.h>
#include <lwip/sockets.h>
#include "esp_transport_http_proxy.h"
#include "esp_transport_internal.h"

static const char *TAG = "trans_http_pxy";
static const size_t MAX_HOST_LEN = 512;
static const size_t MAX_HEADER_LEN = 1024;

typedef struct transport_http_proxy_t {
    uint16_t proxy_port;
    uint32_t alloc_cap;
    esp_transport_handle_t parent;
    char *proxy_host;
    char *user_agent;
} transport_http_proxy_t;

static int get_http_status_code(const char *buffer)
{
    const char http[] = "HTTP/";
    const char *found = strcasestr(buffer, http);
    char status_code[4] = { 0 };
    char *end_ptr = NULL;
    if (found) {
        found += sizeof(http)/sizeof(http[0]) - 1;
        found = strchr(found, ' ');
        if (found) {
            found++;
            strncpy(status_code, found, 4);
            status_code[3] = '\0';
            int code = (int)strtol(status_code, &end_ptr, 10);
            ESP_LOGD(TAG, "HTTP status code is %d", code);
            return code == 0 ? -1 : code;
        }
    }

    return -1;
}

static int http_proxy_connect(esp_transport_handle_t transport, const char *const host, int port, int timeout_ms)
{
    if (transport == NULL) {
        ESP_LOGE(TAG, "Transport context is null at connect!");
        return -1;
    }

    transport_http_proxy_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        ESP_LOGE(TAG, "Internal context is null at connect!");
        return -1;
    }

    char *connect_header = heap_caps_calloc(MAX_HEADER_LEN, sizeof(char), handle->alloc_cap);
    if (connect_header == NULL) {
        ESP_LOGE(TAG, "Failed to allocate header buffer");
        return -2;
    }

    ESP_LOGI(TAG, "Connecting to proxy host: %s at port %u", handle->proxy_host, handle->proxy_port);
    int connect_ret = esp_transport_connect(handle->parent, handle->proxy_host, handle->proxy_port, timeout_ms);
    if (connect_ret < 0) {
        ESP_LOGE(TAG, "Parent transport method connect fail: %d", connect_ret);
        free(connect_header);
        return connect_ret;
    }

    ESP_LOGI(TAG, "Connecting to host via proxy: %s:%d", host, port);
    snprintf(connect_header, MAX_HEADER_LEN, "CONNECT %s:%u HTTP/1.1\r\n"
                                             "Host: %s\r\n"
                                             "Proxy-Connection: keep-alive\r\n"
                                             "User-Agent: %s\r\n"
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

    int status_code = get_http_status_code(connect_header);
    if (status_code < 0) {
        ESP_LOGE(TAG, "Invalid CONNECT response - can't even find status code?");
        free(connect_header);
        return -1;
    }

    if (status_code != 200) {
        ESP_LOGE(TAG, "CONNECT responded with failed status code: %d", status_code);
        free(connect_header);
        return -1;
    }

    free(connect_header);
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
        return ESP_ERR_INVALID_ARG; // Might have been freed before??
    }

    if (handle->user_agent != NULL) free(handle->user_agent);
    if (handle->proxy_host != NULL) free(handle->proxy_host);

    free(handle);

    return ESP_OK;
}

esp_transport_handle_t esp_transport_http_proxy_init(esp_transport_handle_t parent_handle, const esp_transport_http_proxy_config_t *config)
{
    if (parent_handle == NULL || config == NULL) {
        return NULL;
    }

    esp_transport_handle_t transport = esp_transport_init();

    // I know this is shit, but I have no choice...
    // Upstream tcp-transport doesn't expose the foundation pointer, so I have to have some dirty hacks here...
    // This has to be here, otherwise transport_ws won't work with this HTTP proxy handle
    if (parent_handle->foundation == NULL) {
        transport->foundation = parent_handle->foundation;
    } else {
        transport->foundation = esp_transport_init_foundation_transport(); // Might be just a placeholder
    }


    if (transport == NULL) {
        ESP_LOGE(TAG, "Failed to create transport handle");
        return NULL;
    }

    transport_http_proxy_t *proxy_handle = heap_caps_calloc(1, sizeof(transport_http_proxy_t), config->alloc_cap_flag);
    if (proxy_handle == NULL) {
        ESP_LOGE(TAG, "Failed to allocate proxy handle");
        esp_transport_destroy(transport);
        return NULL;
    }

    proxy_handle->parent = parent_handle;
    proxy_handle->proxy_port = config->proxy_port;
    proxy_handle->alloc_cap = config->alloc_cap_flag;
    proxy_handle->proxy_host = heap_caps_calloc(strnlen(config->proxy_host, MAX_HOST_LEN) + 1, sizeof(char), proxy_handle->alloc_cap);
    if (proxy_handle->proxy_host == NULL) {
        ESP_LOGE(TAG, "Failed to allocate proxy host string");
        esp_transport_destroy(transport);
        return NULL;
    }

    strncpy(proxy_handle->proxy_host, config->proxy_host, MAX_HOST_LEN);

    if (config->user_agent != NULL) {
        proxy_handle->user_agent = heap_caps_calloc(strnlen(config->user_agent, MAX_HOST_LEN) + 1, sizeof(char), proxy_handle->alloc_cap);
        if (proxy_handle->user_agent == NULL) {
            ESP_LOGE(TAG, "Failed to allocate proxy user-agent string");
            esp_transport_destroy(transport);
            return NULL;
        }

        strncpy(proxy_handle->user_agent, config->user_agent, MAX_HOST_LEN);
    }

    esp_transport_set_func(transport, http_proxy_connect, http_proxy_read, http_proxy_write, http_proxy_close, http_proxy_poll_read, http_proxy_poll_write, http_proxy_destroy);
    esp_transport_set_context_data(transport, proxy_handle);

    return transport;
}
