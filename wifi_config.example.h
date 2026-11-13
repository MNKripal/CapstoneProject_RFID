// Copy this file to wifi_config.h (which git ignores) and fill in your values.
// If wifi_config.h is absent the firmware builds without Wi-Fi and uses USB only.
#pragma once

#define WIFI_SSID        "YourHotspotName"        // WPA2 personal only; eduroam (enterprise) will not work
#define WIFI_PASSWORD    "YourHotspotPassword"
#define SERVER_HOST      "192.168.1.20"           // IP of the laptop running dashboard/server.py (same network)
#define SERVER_PORT      8080                     // start the server with: python3 server.py --host 0.0.0.0
#define DEVICE_KEY       "paste-dashboard/device_key.txt-here"
