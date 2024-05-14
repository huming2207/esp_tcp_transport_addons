#pragma once

#include <stdint.h>
#include <esp_err.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t timeout_threshold_ms;
    uint32_t slowdown_threshold_ms;
} transport_net_mon_config_t;

esp_err_t esp_transport_net_monitor_create();

#ifdef __cplusplus
}
#endif //__cplusplus