#include <esp_transport.h>
#include "esp_transport_net_mon.h"

typedef struct {

} transport_net_mon_instance_t;

static int net_mon_connect(esp_transport_handle_t handle, const char *host, int port, int timeout_ms)
{
    return 0;
}

static int net_mon_write(esp_transport_handle_t handle, const char *buffer, int len, int timeout_ms)
{
    return 0;
}

static int net_mon_read(esp_transport_handle_t handle, char *buffer, int len, int timeout_ms)
{
    return 0;
}

static int net_mon_poll_read(esp_transport_handle_t handle, int timeout_ms)
{
    return 0;
}

static int net_mon_poll_write(esp_transport_handle_t handle, int timeout_ms)
{
    return 0;
}

static int net_mon_close(esp_transport_handle_t handle)
{
    return 0;
}

static int net_mon_destroy(esp_transport_handle_t handle)
{
    return 0;
}

static int net_mon_connect_async(esp_transport_handle_t handle, const char *host, int port, int timeout_ms)
{
    return 0;
}

esp_err_t esp_transport_net_monitor_create(const transport_net_mon_config_t *config, esp_transport_handle_t *new_netmon_handle, esp_transport_handle_t parent_handle, esp_transport_handle_t child_handle)
{
    return ESP_OK;
}
