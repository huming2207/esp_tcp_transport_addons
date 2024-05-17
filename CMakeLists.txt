idf_component_register(
        SRCS
            "esp_transport_http_proxy.c" "esp_transport_http_proxy.h"
            "esp_transport_sub_tls.c" "esp_transport_sub_tls.h"
            "esp_transport_net_mon.c" "esp_transport_net_mon.h"
        INCLUDE_DIRS
            .
        PRIV_INCLUDE_DIRS
            "${IDF_PATH}/components/esp-tls/private_include" "${IDF_PATH}/components/tcp_transport/private_include"
        REQUIRES
            tcp_transport mbedtls http_parser
)
