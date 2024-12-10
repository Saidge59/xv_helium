#ifndef TUN_ADAPTER_H
#define TUN_ADAPTER_H

#include <helium.h>

/// This is the public API

void he_tun_init(he_server_t *state);
void he_tun_start(he_server_t *state);

/// These are exposed for testing

void on_tun_event(uv_poll_t *handle, int status, int events);
he_return_code_t tun_inside_write_cb(he_conn_t *he_conn, uint8_t *packet, size_t length,
                                     void *context);

#endif
