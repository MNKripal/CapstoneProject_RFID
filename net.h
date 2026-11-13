// Minimal Wi-Fi + HTTP POST client for the reader (Pico 2 W, lwIP raw API).
// Everything is non-blocking: call net_poll() from the main loop.
#pragma once
#include <stdbool.h>
#include <stdint.h>

// Called from net_poll() (main-loop context) when a request finishes.
// status: HTTP status code, or 0 if the request failed (no connection, timeout).
typedef void (*net_cb_t)(int status, const char *body, void *user);

void net_start(const char *ssid, const char *password);   // begins connecting; returns at once
void net_poll(void);                                        // drive reconnects, timeouts, callbacks
bool net_connected(void);                                   // link up and we have an IP
const char *net_ip(void);                                   // dotted IP or "-"
bool net_busy(void);                                        // a request is in flight
// One request at a time. Returns false if busy or not connected.
bool net_post(const char *host, uint16_t port, const char *path, const char *device_key,
              const char *json, net_cb_t cb, void *user);
