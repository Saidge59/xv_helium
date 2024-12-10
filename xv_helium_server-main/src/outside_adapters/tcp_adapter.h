#ifndef TCP_ADAPTER_H
#define TCP_ADAPTER_H

#include <helium.h>

/// This is the public API
void he_tcp_init(he_server_t *state);
void he_tcp_start(he_server_t *state);
void he_tcp_stop(he_server_t *state);

/// These internal APIs are exposed for testing
/// These functions implement that path that Helium packets travel from lightway-core to the
/// TCP socket
void on_send_streaming(uv_write_t *req, int status);
he_return_code_t tcp_write_cb(he_conn_t *he_conn, uint8_t *packet, size_t length, void *context);

/// These functions implement that path that Helium packets travel from the TCP socket to
/// lightway-core
void on_new_streaming_connection(uv_stream_t *server, int status);
void on_tcp_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf);
void on_tcp_stopped(uv_handle_t *server);
void he_tcp_outside_stream_received(he_server_connection_t *conn, uint8_t *data, size_t length);

#endif  // TCP_GW_H
