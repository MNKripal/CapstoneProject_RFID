// Copy this file to wifi_config.h (which git ignores) and fill in your values.
// If wifi_config.h is absent the firmware builds without Wi-Fi and uses USB only.
#pragma once

#define WIFI_SSID        "YourHotspotName"        // WPA2 personal, 2.4 GHz only; eduroam (enterprise) will not work
#define WIFI_SSID_ALT    ""                       // optional second spelling to try (iPhones use a curly apostrophe: Kripal’s iPhone)
#define WIFI_PASSWORD    "YourHotspotPassword"
#define SERVER_HOST      "192.168.1.20"           // IP of the laptop running dashboard/server.py (same network)
#define SERVER_PORT      8080                     // start the server with: python3 server.py --host 0.0.0.0
#define DEVICE_KEY       "paste-dashboard/device_key.txt-here"
// Optional fixed address. iPhone hotspots often never answer the Pico's DHCP request;
// they always use 172.20.10.1/28, so pick an address in 172.20.10.2-14. Leave these out for DHCP.
// #define STATIC_IP     "172.20.10.14"
// #define STATIC_MASK   "255.255.255.240"
// #define STATIC_GW     "172.20.10.1"
