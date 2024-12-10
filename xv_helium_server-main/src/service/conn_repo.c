#include "conn_repo.h"

#include "inside_ip_repo.h"
#include "key_hash_methods.h"
#include "util.h"
#include "plugin_service.h"
#include "statistics.h"

void he_conn_repo_init_start(he_server_t *state) {
  ip_port_connection_map_init(&state->connections_by_external_ip_and_port);
  session_connection_map_init(&state->connections_by_session);
  session_connection_map_init(&state->connections_by_pending_session);
}

void he_update_connection_address(he_server_connection_t *conn, const struct sockaddr *addr,
                                  he_v4_ip_port_t ipcombo) {
  // Update the return address for traffic
  memcpy(&conn->addr, addr, sizeof(conn->addr));

  // Change the key in the hashmap
  ip_port_connection_map_change_key(&conn->state->connections_by_external_ip_and_port,
                                    conn->external_ip_port, ipcombo);

  // Update the ip pair in the structure
  conn->external_ip_port = ipcombo;
}

void on_renegotiation_timer(uv_timer_t *timer) {
  // Grab connection context
  he_server_connection_t *conn = (he_server_connection_t *)timer->data;
  HE_CHECK_WITH_MSG(conn, "No connection supplied in renegotiation timer");
  he_conn_schedule_renegotiation(conn->he_conn);
}

void he_connection_start_renegotiation_timer(he_server_connection_t *conn) {
  // Start the timer
  int renegotiation_time_ms = conn->state->renegotiation_timer_min * HE_MINUTE_MS;
  uv_timer_start(&conn->renegotiation_timer, on_renegotiation_timer, renegotiation_time_ms,
                 renegotiation_time_ms);
}

void he_begin_session_id_rotation(he_server_connection_t *conn) {
  // The client already has a pending session change that they did not accept
  if(conn->pending_session != HE_PACKET_SESSION_EMPTY) {
    return;
  }

  uint64_t pending_session = 0;

  int res = he_conn_rotate_session_id(conn->he_conn, &pending_session);

  if(res != HE_SUCCESS) {
    // Maybe a session rotation started that we did not take note of, belt and bracers here
    pending_session = he_conn_get_pending_session_id(conn->he_conn);
    if(pending_session == 0) {
      return;
    }
  }

  conn->pending_session = pending_session;

  session_connection_map_set(&conn->state->connections_by_pending_session, conn->pending_session,
                             conn);

  he_statistics_report_metric(conn, HE_METRIC_SESSION_ROTATION_BEGIN);
}

void he_finalize_session_id_rotation(he_server_connection_t *conn) {
  // This should not have triggered - conn has no pending session
  if(conn->pending_session == HE_PACKET_SESSION_EMPTY) {
    return;
  }

  session_connection_map_remove(&conn->state->connections_by_pending_session,
                                conn->pending_session);

  session_connection_map_remove(&conn->state->connections_by_session, conn->cur_session);

  conn->cur_session = conn->pending_session;

  bool consistent_check = conn->cur_session == he_conn_get_session_id(conn->he_conn);

  HE_CHECK_WITH_MSG(consistent_check, "Session ID rotation resulted in inconsistent state");

  session_connection_map_set(&conn->state->connections_by_session, conn->cur_session, conn);

  conn->pending_session = HE_PACKET_SESSION_EMPTY;

  he_statistics_report_metric(conn, HE_METRIC_SESSION_ROTATION_FINALIZE);
}

void he_remove_from_maps(he_server_connection_t *conn) {
  // Remove connection from mapping
  // We don't populate this map for TCP connections, but it's safe to delete regardless
  ip_port_connection_map_remove(&conn->state->connections_by_external_ip_and_port,
                                conn->external_ip_port);

  // We never create a connection without putting it into the session map
  session_connection_map_remove(&conn->state->connections_by_session, conn->cur_session);

  // Connections can exist without an assigned IP
  if(conn->inside_ip) {
    he_release_inside_ip(conn);
  }

  // Remove pending session from the map if it is set
  // NOTE: The hashmap would be fine without the if condition
  // but this guard avoids an unnecessary linear scan
  if(conn->pending_session) {
    session_connection_map_remove(&conn->state->connections_by_pending_session,
                                  conn->pending_session);
  }
}

/**
 * After a call to free_connection all connection memory will be free'd.
 * NOTE: Subsequent usage of conn, or wolfSSL read and write will crash helium.
 */
static void he_free_connection(he_server_connection_t *conn) {
  // There's at least one hypothetical path where we end up here w/o a conn object,
  // where we close a TCP connection due to a failed accept and/or a failed connection
  // creation.
  if(conn) {
    he_free_plugin_set(&conn->tcp_plugin_set);
    he_free_plugin_set(&conn->udp_send_plugin_set);

    he_conn_destroy(conn->he_conn);
    // Zero out the SSL session
    memset(conn, 0, sizeof(he_server_connection_t));
    jefree(conn);
  }
}

static void he_conn_clear_triggers(he_server_connection_t *conn) {
  uv_timer_stop(&conn->renegotiation_timer);
  if(conn->state->connection_type == HE_CONNECTION_TYPE_DATAGRAM) {
    uv_timer_stop(&conn->he_timer);
  }
}

static void he_free_connection_callback(uv_handle_t *handle) {
  if(handle->data) {
    he_free_connection((he_server_connection_t *)handle->data);
  }
}

static void he_close_renegotiation_timer_cb(uv_handle_t *handle) {
  if(handle->data) {
    he_server_connection_t *conn = (he_server_connection_t *)handle->data;
    uv_close((uv_handle_t *)&conn->renegotiation_timer, he_free_connection_callback);
  }
}

void he_post_disconnect_cleanup(he_server_connection_t *conn) {
  // Clear any timers or triggers for callbacks that would be conn state as an argument
  he_conn_clear_triggers(conn);

  // Remove references to a connection from the state
  he_remove_from_maps(conn);

  // Either way, the next step is always closing the renegotiation timer
  if(conn->state->connection_type == HE_CONNECTION_TYPE_DATAGRAM) {
    uv_close((uv_handle_t *)&conn->he_timer, he_close_renegotiation_timer_cb);
    return;
  }

  // TCP Close
  if (conn->tcp_client_initialized) {
    uv_close((uv_handle_t *)&conn->tcp_client, he_close_renegotiation_timer_cb);
  } else {
    // If TCP client hasn't been intialized we still need to close the reneg timer
    uv_close((uv_handle_t *)&conn->renegotiation_timer, he_free_connection_callback);
  }
}
