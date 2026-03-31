# HTTP Proxy support plugin for ESP-IDF TCP transport

## Introduction

This is an out-of-tree (out of ESP-IDF SDK) component library for enabling HTTP/HTTPS proxy support for anything that uses `tcp_transport`, such as HTTP client, WebSocket client, MQTT clients or any self-defined `tcp_transport` handles.

## Usage 

For example, if you want to set up an HTTPS or WSS over a HTTPS proxy, try this:

```c++
esp_transport_handle_t https_proxied_handle = nullptr;
esp_transport_http_proxy_config_t proxy_config = {};
proxy_config.is_https_proxy = true;
proxy_config.proxy_host = "your.proxy.server.host";
proxy_config.proxy_port = 443;
proxy_config.server_tls.use_global_ca_store = true;

auto ret = esp_transport_http_proxy_init(&https_proxied_handle, &proxy_config);
if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Proxy creation failed: 0x%x %s", ret, esp_err_to_name(ret));
    return ret;
}
```

...then the `https_proxied_handle` is the TCP transport handle you want to play with, e.g. call `esp_transport_write()` to send stuff.

## Disclaimer 声明

This project is intended to let an ESP32 device to access external servers from some commercial entities' internal network. This project itself will NOT provide any encryption or obfuscation support, and it is NOT for bypassing any government law enforcement & regulations. Please DO NOT raise any issues or pull requests if you have such demand. All discussions related to fleeing law enforcements will be removed.

此项目主要目的是为了让ESP32能在相关企业内网通过其代理连接外部接口，并非用于规避政府执法与监管，且此项目本身并不提供任何加密、协议混淆功能。若有此类需求请另请高明，任何与规避监管相关的issue和PR都会被删除。

## License

MIT

Copyright (C) 2025, Jackson Ming Hu at SmartGuide Pty Ltd
