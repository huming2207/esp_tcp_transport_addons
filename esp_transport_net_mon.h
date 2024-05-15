#pragma once

#include <stdint.h>
#include <esp_err.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    esp_transport_handle_t parent_handle;
    esp_transport_handle_t child_handle;
    uint32_t accum_latency_threshold; // Latency threshold (in milliseconds) for historical accumulation
    uint32_t timeout_threshold; // Timeout threshold for a single transaction, in milliseconds
    uint32_t timeout_count_threshold; // Timeout count threshold for a client, in counts
    char instance_name[16];
} transport_net_mon_config_t;

esp_err_t esp_transport_net_monitor_create(const transport_net_mon_config_t *config, esp_transport_handle_t *new_netmon_handle, esp_transport_handle_t parent_handle, esp_transport_handle_t child_handle);

#ifdef __cplusplus
}
#endif //__cplusplus