#pragma once

#include <stdint.h>
#include <esp_err.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    esp_transport_handle_t parent_handle;
    esp_transport_handle_t child_handle;
    uint32_t timeout_ms_thresh;
    uint32_t slowdown_ms_thresh;
    uint32_t timeout_count_thresh;
    uint32_t slowdown_count_thresh;
    uint32_t open_retry_count_thresh;
    uint64_t instance_id;
} transport_net_mon_config_t;

esp_err_t esp_transport_net_monitor_create(const transport_net_mon_config_t *config, esp_transport_handle_t *new_netmon_handle, esp_transport_handle_t parent_handle, esp_transport_handle_t child_handle);

#ifdef __cplusplus
}
#endif //__cplusplus