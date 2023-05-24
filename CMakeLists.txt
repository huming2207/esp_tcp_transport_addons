idf_component_register(
        SRCS
            esp_transport_http_proxy.c esp_transport_http_proxy.h
            dirty_hack/esp_transport_internal.h
        INCLUDE_DIRS
            .
        PRIV_INCLUDE_DIRS
            "dirty_hack"
        REQUIRES
            tcp_transport
)