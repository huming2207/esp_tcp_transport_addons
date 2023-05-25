#include <esp_tls.h>
#include <esp_log.h>
#include "esp_transport_internal.h"
#include "esp_transport_sub_tls.h"

static const char *TAG = "trans_sub_tls";

typedef struct transport_sub_tls {
    int sock_fd;
    esp_tls_t *tls;
    esp_tls_cfg_t cfg;
    esp_transport_handle_t parent;
} transport_sub_tls_t;

static int sub_tls_connect(esp_transport_handle_t transport, const char *const host, int port, int timeout_ms)
{
    transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL || handle->parent == NULL || handle->parent->_get_socket == NULL) {
        ESP_LOGE(TAG, "Unsupported parent transport");
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

    // Here we assume we have a connection already, and we "fast-track" the state to handshake only
    esp_err_t ret = esp_tls_set_conn_state(handle->tls, ESP_TLS_CONNECTING);

    // We also manually provide the socket FD to esp-tls to let it does its job
    ret = ret ?: esp_tls_set_conn_sockfd(handle->tls, sock_fd);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed when setting up ESP-TLS state: 0x%x", ret);
        return -3;
    }

    conn_ret = esp_tls_conn_new_sync(host, (int)strlen(host), port, &handle->cfg, handle->tls);
    if (conn_ret != 1) {
        ESP_LOGE(TAG, "TLS setup/handshake failed: %d", conn_ret);
        return -4;
    }

    return 0;
}

static int sub_tls_close(esp_transport_handle_t transport)
{
    transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        return -1;
    }

    int ret = esp_tls_conn_destroy(handle->tls);
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

    if ((poll = esp_transport_poll_write(transport, timeout_ms)) <= 0) {
        ESP_LOGW(TAG, "Write poll timeout or error, errno=%s, fd=%d, timeout_ms=%d", strerror(errno), handle->sock_fd, timeout_ms);
        return poll;
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

    int poll = esp_transport_poll_read(transport, timeout_ms);
    if (poll == -1) {
        ESP_LOGW(TAG, "Read poll error, errno=%s, fd=%d, timeout_ms=%d", strerror(errno), handle->sock_fd, timeout_ms);
        return ERR_TCP_TRANSPORT_CONNECTION_FAILED;
    }

    if (poll == 0) {
        ESP_LOGE(TAG, "Read poll timeout, errno=%s, fd=%d, timeout_ms=%d", strerror(errno), handle->sock_fd, timeout_ms);
        return ERR_TCP_TRANSPORT_CONNECTION_TIMEOUT;
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

    return esp_transport_poll_read(transport, timeout_ms);
}

static int sub_tls_poll_write(esp_transport_handle_t transport, int timeout_ms)
{
    transport_sub_tls_t *handle = esp_transport_get_context_data(transport);
    if (handle == NULL) {
        return -1;
    }

    return esp_transport_poll_write(transport, timeout_ms);
}

static esp_err_t sub_tls_destroy(esp_transport_handle_t transport)
{
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

esp_err_t esp_transport_sub_tls_init(esp_transport_handle_t *new_handle, esp_transport_handle_t parent_handle, const esp_transport_sub_tls_t *config)
{
    if (new_handle == NULL || parent_handle == NULL || config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_transport_handle_t transport = esp_transport_init();
    if (transport == NULL) {
        ESP_LOGE(TAG, "Failed to create transport handle");
        return ESP_FAIL;
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
    handle->cfg.non_block = false; // Seems like this is needed - otherwise it will do the select() crap

    *new_handle = transport;
    return ESP_OK;
}
