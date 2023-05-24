#pragma once

#include <stdint.h>
#include <esp_transport.h>

/**
 * Configuration struct
 */
typedef struct esp_transport_sub_tls {
    bool use_global_ca_store;
    const char *cert;
    size_t cert_len;
    const char *client_cert;
    size_t client_cert_len;
    const char *client_key;
    size_t client_key_len;
    bool skip_cert_common_name_check;
    esp_err_t (*crt_bundle_attach)(void *conf);
} esp_transport_sub_tls_t;

