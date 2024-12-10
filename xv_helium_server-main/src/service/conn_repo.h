#ifndef CONN_REPO_H
#define CONN_REPO_H

#include <helium.h>

/// See discussion in conn_service.h for the difference between these two modules

void he_conn_repo_init_start(he_server_t *state);

void he_update_connection_address(he_server_connection_t *conn, const struct sockaddr *addr,
                                  he_v4_ip_port_t ipcombo);

void he_connection_start_renegotiation_timer(he_server_connection_t *conn);

void on_renegotiation_timer(uv_timer_t *timer);

/**
 * Begins the process of changing a clients session ID
 */
void he_begin_session_id_rotation(he_server_connection_t *conn);

/**
 * Accepts a pending session ID rotations, replacing session and clearing the session ID
 */
void he_finalize_session_id_rotation(he_server_connection_t *conn);

void he_post_disconnect_cleanup(he_server_connection_t *conn);
#endif  // CONN_REPO_H
