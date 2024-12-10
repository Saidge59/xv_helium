#ifndef UDP_ADAPTER_H
#define UDP_ADAPTER_H

#include "helium.h"

/// This is the public API
void he_udp_init(he_server_t *state);
void he_udp_start(he_server_t *state);

/// These internal APIs are exposed for testing
/// These callbacks implement the D/TLS nudge machinery
he_return_code_t nudge_time_cb(he_conn_t *he_conn, int timeout, void *context);
void on_he_nudge(uv_timer_t *timer);

/// These functions implement that path that Helium packets travel from lightway-core to the
/// UDP socket and ultimately to the client

void on_send_complete(uv_udp_send_t *req, int status);
he_return_code_t udp_write_cb(he_conn_t *he_conn, uint8_t *packet, size_t length, void *context);

/// These functions implement that path that Helium packets travel from the UDP socket to
/// lightway-core
void on_read(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr,
             const struct sockaddr *dst, unsigned flags);

void he_udp_process_valid_packet(he_server_t *server, uv_udp_t *udp_socket, const uv_buf_t *he_pkt,
                                 int he_pkt_len, const struct sockaddr *addr,
                                 const struct sockaddr *dst);

void he_session_reject(uv_udp_t *udp_socket, const struct sockaddr *addr, const struct sockaddr *src);

#endif  // UDP_GW_H
