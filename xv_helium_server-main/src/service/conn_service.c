#include "conn_service.h"
#include "util.h"
#include "plugin_service.h"
#include "conn_repo.h"

void he_connection_change_of_address(he_server_connection_t *conn, const struct sockaddr *addr,
                                     he_v4_ip_port_t ipcombo) {
  // We just call this here, the logic of "only start one if there's not one already" is handled
  // elsewhere.
  he_begin_session_id_rotation(conn);

  he_update_connection_address(conn, addr, ipcombo);
}

void he_connection_disconnect(he_server_connection_t *conn) {
  int res = he_conn_disconnect(conn->he_conn);

  if(res != HE_SUCCESS) {
    // This function is already called via the event handler if and only if res is HE_SUCCESS
    // For our purposes we don't care whether HE_SUCCESS is returned or not however, since we
    // want this client to be dead after this function invocation.
    //
    // Note that we guard this since calling this function twice can result in use-after-free.
    he_post_disconnect_cleanup(conn);
  }
}

he_server_connection_t *he_find_connection(he_server_t *state, uint64_t session,
                                           he_v4_ip_port_t ipcombo, bool *update_source) {
  // Start with an empty ptr for conn
  he_server_connection_t *conn = NULL;

  // Try to find the session by clients IP and port
  bool found_ip_combo =
      ip_port_connection_map_find(&state->connections_by_external_ip_and_port, ipcombo, &conn);

  // If we found it exit with the conn
  if(found_ip_combo) {
    return conn;
  }

  // If the session wasn't found, and a session ID is set, try to look up the session by the session
  // ID NOTE: this will reject sessions which have a non-zero session ID but can't be found
  bool found_session_conn =
      session_connection_map_find(&state->connections_by_session, session, &conn);

  // If the session ID is not found in the session ID map there
  // is a chance that they acknowledged a new session ID immediately prior
  // to changing network
  if(!found_session_conn) {
    found_session_conn =
        session_connection_map_find(&state->connections_by_pending_session, session, &conn);
  }

  if(!found_session_conn) {
    return NULL;
  }

  // If port scatter is enabled, the packet may be coming from different client ports. To avoid
  // polluting the "recovered_session" metric, we only increment it when port scatter is disabled.
  // This means we won't be able to track the "recovered session" count on port scatter instances.
  if(!state->port_scatter) {
    // Session was recovered
    statsd_inc(state->statsd, HE_METRIC_RECOVERED_SESSION, 1);
  }

  // We should update the IP and combo later if the packet is safely decrypted
  *update_source = true;

  return conn;
}

static he_server_connection_t *internal_create_connection(he_server_t *state) {
  he_server_connection_t *conn = jecalloc(1, sizeof(he_server_connection_t));

  HE_CHECK_WITH_MSG(conn != NULL, "Unable to allocate new connection");

  conn->state = state;

  // Create the Helium connection
  conn->he_conn = he_conn_create();
  HE_CHECK_WITH_MSG(conn->he_conn != NULL, "Unable to allocate new Helium connection");

  // Set up the Renegotiation timer timer
  if(uv_timer_init(state->loop, &conn->renegotiation_timer)) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error: Could not initialise the renegotiation timer!\n");
    goto cleanup;
  }

  conn->renegotiation_timer.data = conn;

  // Increment the counter
  state->stats_session_count++;
  conn->stats_connection_started = uv_hrtime();

  return conn;
cleanup:
  HE_FLOW_DISPATCH(he_connection_disconnect, conn);
  return NULL;
}

static he_return_code_t internal_start_connection(he_server_t *state,
                                                  he_server_connection_t *conn) {
  // Actually connect libhelium
  HE_SUCCESS_OR_RETURN(he_conn_set_outside_mtu(conn->he_conn, HE_MAX_WIRE_MTU),
                       "Unable to set MTU");

  HE_SUCCESS_OR_RETURN(he_conn_set_context(conn->he_conn, conn),
                       "Unable to set the connection context");

  HE_SUCCESS_OR_RETURN(he_conn_server_connect(conn->he_conn, state->he_ctx, NULL, NULL),
                       "Unable to connect");

  // Generate a 64 bit random value to use
  conn->cur_session = he_conn_get_session_id(conn->he_conn);
  conn->pending_session = HE_PACKET_SESSION_EMPTY;

  // Log the session creation
  zlogf_time(ZLOG_INFO_LOG_MSG, "New session created: %zx\n",
             he_conn_get_session_id(conn->he_conn));

  session_connection_map_set(&state->connections_by_session, he_conn_get_session_id(conn->he_conn),
                             conn);

  return HE_SUCCESS;
}

he_server_connection_t *he_create_new_connection(he_server_t *state, const struct sockaddr *addr,
                                                 const struct sockaddr *dst,
                                                 he_v4_ip_port_t ipcombo, uint8_t major_version,
                                                 uint8_t minor_version) {
  // Allocate some space
  he_server_connection_t *conn = internal_create_connection(state);

  if(conn == NULL) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error: Could not create connection\n");
    return NULL;
  }

  // Set the protocol version
  HE_SUCCESS_OR_CLEANUP(he_conn_set_protocol_version(conn->he_conn, major_version, minor_version),
                        "Error: Could not set protocol version");

  // Create the plugins for sending
  he_init_plugin_set(state, &conn->udp_send_plugin_set);

  // Copy in the clients IP address
  memcpy(&conn->addr, addr, sizeof(struct sockaddr));

  // Set up the Helium timer (only needed for D/TLS)
  HE_SUCCESS_OR_CLEANUP(uv_timer_init(state->loop, &conn->he_timer),
                        "Error: Could not initialise the wolf timer!");

  // Add the connection context
  conn->he_timer.data = conn;

  // Set IP port combo for use as a key
  conn->external_ip_port = ipcombo;

  // Add to hashmaps
  ip_port_connection_map_set(&state->connections_by_external_ip_and_port, conn->external_ip_port,
                             conn);

  // Set up DIP address
  if(state->is_dip_enabled) {
    if(dst && dst->sa_family == AF_INET) {
      const struct sockaddr_in *dst_in = (const struct sockaddr_in *)dst;
      conn->dip_addr.sin_addr.s_addr = dst_in->sin_addr.s_addr;
      conn->dip_addr.sin_port = state->bind_port;
      conn->dip_addr.sin_family = AF_INET;
    } else {
      HE_SUCCESS_OR_CLEANUP(HE_ERR_BAD_PACKET, "Error: Invalid destination address");
    }
  }
  HE_SUCCESS_OR_CLEANUP(internal_start_connection(state, conn),
                        "Error: Could not start connection");

  return conn;
cleanup:
  HE_FLOW_DISPATCH(he_connection_disconnect, conn);
  return NULL;
}

he_server_connection_t *he_create_new_connection_streaming(he_server_t *state) {
  // Allocate some space
  he_server_connection_t *conn = internal_create_connection(state);

  if(conn == NULL) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error: Could not create connection\n");
    return NULL;
  }

  // Set the protocol version -- hardcoded for now
  HE_SUCCESS_OR_CLEANUP(he_conn_set_protocol_version(conn->he_conn, 1, 0),
                        "Error: Could not set protocol version");

  he_init_plugin_set(state, &conn->tcp_plugin_set);

  HE_SUCCESS_OR_CLEANUP(internal_start_connection(state, conn),
                        "Error: Could not start connection");

  return conn;

cleanup:
  HE_FLOW_DISPATCH(he_connection_disconnect, conn);
  return NULL;
}

static void internal_disconnect_cb(session_connection_map_entry_t *entry) {
  he_connection_disconnect(entry->data);
}

static bool internal_get_all_connections(session_connection_map_entry_t *entry) {
  return true;
}

void he_disconnect_all_connections(he_server_t *state) {
  session_connection_map_delete_matching(&state->connections_by_session,
                                         internal_get_all_connections, internal_disconnect_cb);
}
