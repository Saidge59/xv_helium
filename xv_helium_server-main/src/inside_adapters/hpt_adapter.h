#ifndef HPT_ADAPTER_H
#define HPT_ADAPTER_H

#include <helium.h>

/// This is the public API
void he_hpt_init(he_server_t *state);
void he_hpt_start(he_server_t *state);

/// These are exposed for testing
void on_hpt_event(uv_poll_t *handle, int a, int b);
void on_hpt_packet(void *handle, uint8_t *msg_content, size_t length);
he_return_code_t hpt_inside_write_cb(he_conn_t *he_conn, uint8_t *packet, size_t length,
                                     void *context);

#endif
