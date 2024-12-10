#include "udp_adapter.h"

#include "conn_service.h"
#include "plugin_service.h"
#include "statistics.h"

#include "util.h"

static void he_internal_udp_init(he_server_t *state) {
  // Set the appropriate callbacks
  he_ssl_ctx_set_outside_write_cb(state->he_ctx, udp_write_cb);
  he_ssl_ctx_set_nudge_time_cb(state->he_ctx, nudge_time_cb);

  // Set up IP and port
  struct sockaddr_in recv_addr;
  int res = uv_ip4_addr(state->bind_ip, state->bind_port, &recv_addr);
  if(res) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Invalid IP address or port - %s\n",
               uv_strerror(res));
    zlog_finish();
    HE_EXIT_WITH_FAILURE();
  }

  // Initialise UDP socket
  res = uv_udp_init_ex(state->loop, &state->udp_socket, UV_UDP_RECVMMSG);
  if(res) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Cannot initialise UDP socket - %s\n",
               uv_strerror(res));
    zlog_finish();
    HE_EXIT_WITH_FAILURE();
  }

  // Bind UDP socket to IP and port
  res = uv_udp_bind(&state->udp_socket, (const struct sockaddr *)&recv_addr,
                    UV_UDP_REUSEADDR | UV_UDP_PKTINFO);
  if(res) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Could not bind UDP socket to IP and port - %s\n",
               uv_strerror(res));
    zlog_finish();
    HE_EXIT_WITH_FAILURE();
  }

  uv_send_buffer_size((uv_handle_t *)&state->udp_socket, &state->udp_buffer_size);
  uv_recv_buffer_size((uv_handle_t *)&state->udp_socket, &state->udp_buffer_size);

  // Add global state to the socket for easy lookup
  state->udp_socket.data = state;
}

static void he_internal_udp_port_scatter_init(he_server_t *state) {
  // Bind to more ports
  for(int i = 0; i < HE_PORT_SCATTER_MAX_PORTS; i++) {
    uint16_t port = state->port_scatter_ports[i];
    if(port == 0) {
      continue;
    }
    // Create a udp socket
    struct sockaddr_in recv_addr = {0};
    int res = uv_ip4_addr(state->bind_ip, port, &recv_addr);
    if(res) {
      zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: invalid ip address - %s\n", uv_strerror(res));
      zlog_finish();
      HE_EXIT_WITH_FAILURE();
    }

    uv_udp_t *udp_socket = &state->port_scatter_sockets[i];
    res = uv_udp_init_ex(state->loop, udp_socket, UV_UDP_RECVMMSG);
    if(res) {
      zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: cannot initialise UDP socket - %s\n",
                 uv_strerror(res));
      zlog_finish();
      HE_EXIT_WITH_FAILURE();
    }

    // Try bind to that port
    res = uv_udp_bind(udp_socket, (const struct sockaddr *)&recv_addr, 0);
    if(res) {
      // The port is probably already used, reset current entry to 0 and move to next slot
      state->port_scatter_ports[i] = 0;
      continue;
    }

    // Set buffer size to 2 MB to keep the memory usage under control
    int udp_buffer_size = 2 * MEGABYTE;
    uv_send_buffer_size((uv_handle_t *)udp_socket, &udp_buffer_size);
    uv_recv_buffer_size((uv_handle_t *)udp_socket, &udp_buffer_size);

    // Add global state to the socket for easy lookup
    udp_socket->data = state;
  }
}

void he_udp_init(he_server_t *state) {
  he_internal_udp_init(state);

  if(state->port_scatter) {
    he_internal_udp_port_scatter_init(state);

    // Print port scatter ports to logs
    char buf[1024] = {0};
    int pos = 0;
    for(int i = 0; i < HE_PORT_SCATTER_MAX_PORTS; i++) {
      if(pos > 0) {
        snprintf(&buf[pos], sizeof(buf) - pos, ",");
        pos++;
      }
      int n = snprintf(&buf[pos], sizeof(buf) - pos, "%d", state->port_scatter_ports[i]);
      if(n < 0) {
        break;
      }
      pos += n;
    }
    zlogf_time(ZLOG_INFO_LOG_MSG, "Port scatter ports: [%s]\n", buf);
    zlog_flush_buffer();
  }
}

void he_udp_start(he_server_t *state) {
  // Start listening for connections
  int res = uv_udp_recv_start(&state->udp_socket, alloc_uv_buffer, on_read);

  if(res) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Could not listen on UDP socket - %s\n",
               uv_strerror(res));
    zlog_finish();
    HE_EXIT_WITH_FAILURE();
  }

  if(state->port_scatter) {
    // Prevent clients using Lightway Core v1.8.0 or earlier from connecting
    // if Port Scatter is enabled. Note this must be called after `he_service_start` otherwise the
    // minimal supported version in the ssl_ctx will be overwritten by Lightway Core.
    if(state->port_scatter) {
      he_return_code_t rc = he_ssl_ctx_set_minimum_supported_version(state->he_ctx, 1, 2);
      if(rc != HE_SUCCESS) {
        zlogf_time(ZLOG_INFO_LOG_MSG,
                   "Fatal Error: Could not set minimal supported version on SSL context - %s\n",
                   he_return_code_name(rc));
        zlog_finish();
        HE_EXIT_WITH_FAILURE();
      }
    }

    // Start listening on incoming data on all port scatter ports
    for(int i = 0; i < HE_PORT_SCATTER_MAX_PORTS; i++) {
      uint16_t port = state->port_scatter_ports[i];
      if(port == 0) {
        continue;
      }
      uv_udp_t *udp_socket = &state->port_scatter_sockets[i];
      int res = uv_udp_recv_start(udp_socket, alloc_uv_buffer, on_read);
      if(res) {
        zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Could not listen on UDP socket - %s\n",
                   uv_strerror(res));
        zlog_finish();
        HE_EXIT_WITH_FAILURE();
      }
    }
  }
}

// Helium Callbacks

he_return_code_t nudge_time_cb(he_conn_t *he_conn, int timeout, void *context) {
  // Get our context back
  he_server_connection_t *conn = (he_server_connection_t *)context;

  // Schedule new timeout
  int rc = uv_timer_start(&conn->he_timer, on_he_nudge, (u_int64_t)timeout, 0);
  if(rc < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error occurred during uv_write: %s\n", uv_strerror(rc));
    return HE_ERR_CALLBACK_FAILED;
  }
  return HE_SUCCESS;
}

void on_he_nudge(uv_timer_t *timer) {
  // Grab connection context
  he_server_connection_t *conn = (he_server_connection_t *)timer->data;

  he_conn_nudge(conn->he_conn);
}

/**
 * This callback is executed after a packet is sent.
 * It will free all related buffers
 */
void on_send_complete(uv_udp_send_t *req, int status) {
  he_send_req_t *send_req = (he_send_req_t *)req;
  jefree(send_req->buf.base);
  jefree(req);
}

he_return_code_t udp_write_cb(he_conn_t *he_conn, uint8_t *packet, size_t length, void *context) {
  // Get our context back
  he_server_connection_t *conn = (he_server_connection_t *)context;

  he_send_req_t *req = (he_send_req_t *)jecalloc(1, sizeof(he_send_req_t));
  HE_CHECK_WITH_MSG(req != NULL, "Unable to allocate write request\n");

  uint8_t *output_buffer = jecalloc(1, HE_MAX_OUTSIDE_MTU);
  HE_CHECK_WITH_MSG(output_buffer != NULL, "Unable to allocate write buffer\n");
  memcpy(output_buffer, packet, length);

  size_t post_plugin_length = length;
  he_return_code_t res = he_plugin_egress(conn->udp_send_plugin_set.plugin_chain, output_buffer,
                                          &post_plugin_length, HE_MAX_OUTSIDE_MTU);

  if(res != HE_SUCCESS) {
    if(res == HE_ERR_PLUGIN_DROP) {
      res = HE_SUCCESS;
    }
    jefree(output_buffer);
    return res;
  }

  // Setup the request
  req->buf = uv_buf_init((char *)output_buffer, post_plugin_length);

  uv_udp_t *udp_socket = NULL;

  // Send the udp packet to client using last used socket
  udp_socket = conn->last_used_udp_socket ? conn->last_used_udp_socket : &conn->state->udp_socket;

  int err = uv_udp_send((uv_udp_send_t *)req, udp_socket, &req->buf, 1,
                        (const struct sockaddr *)&conn->addr,
                        (const struct sockaddr *)&conn->dip_addr, on_send_complete);
  if(err) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error occurred during uv_write: %d\n", err);
    jefree(output_buffer);
    jefree(req);
    return HE_ERR_CALLBACK_FAILED;
  }

  return HE_SUCCESS;
}

// Client->Server Path

bool on_read_check_packet_is_valid_helium(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                                          const struct sockaddr *addr, unsigned flags) {
  // Empty packet - happens after every attempt to read from an empty socket - just free and
  // return
  if(nread == 0) {
    return false;
  }

  // Reject packets that are too small
  if(nread < sizeof(he_wire_hdr_t)) {
    return false;
  }

  // Should be impossible
  if(buf == NULL) {
    return false;
  }

  return true;
}

void on_read(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr,
             const struct sockaddr *dst, unsigned flags) {
  HE_CHECK_WITH_MSG(handle, "Impossible state occurred, uv_udp_t handle was NULL!\n");

  uint64_t on_read_start_time = uv_hrtime();

  // address is NULL when recvmmsg has processed all the packets and the buffer should be free'd
  if(!addr) {
    goto cleanup;
  }

  // Negative reads are socket errors indicating recvmmsg failed, free the packet
  if(nread < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Read Error on UDP socket: %s\n", uv_err_name(nread));
    goto cleanup;
  }

  // Check if this is a valid Helium prefix
  if(!HE_FLOW_DISPATCH_BOOL(on_read_check_packet_is_valid_helium, handle, nread, buf, addr,
                            flags)) {
    // Here we do *not* want to do cleanup, we may have other valid packets coming in to recvmmsg
    return;
  }

  // So far so good - let's get the global state context handy
  he_server_t *state = (he_server_t *)handle->data;
  HE_CHECK_WITH_MSG(state, "Impossible state occurred, server from udp handle was NULL!\n");

  // Now kick off our internal processing
  HE_FLOW_DISPATCH(he_udp_process_valid_packet, state, handle, buf, nread, addr, dst);

  uint64_t on_read_end_time = uv_hrtime();
  statsd_timing_with_sample_rate(state->statsd, HE_METRIC_INCOMING_TIME,
                                 HE_NS_TO_MS(on_read_end_time - on_read_start_time),
                                 state->statsd_sample_rate);

  // Note here that because we use recvmmsg here we do NOT want to fall-through to the cleanup
  // code
  return;

cleanup:
  if(buf) {
    jefree(buf->base);
  }
}

void he_udp_process_valid_packet(he_server_t *server, uv_udp_t *udp_socket, const uv_buf_t *he_pkt,
                                 int he_pkt_len, const struct sockaddr *addr,
                                 const struct sockaddr *dst) {
  size_t post_plugin_length = he_pkt_len;

  int res = he_plugin_ingress(server->udp_recv_plugin_set.plugin_chain, (uint8_t *)he_pkt->base,
                              &post_plugin_length, he_pkt_len);

  if(res == HE_ERR_PLUGIN_DROP) {
    // No need to do anything
    return;
  }

  if(res != HE_SUCCESS) {
    statsd_inc(server->statsd, HE_METRIC_PLUGIN_ERROR, 1);
    return;
  }

  if(post_plugin_length < sizeof(he_wire_hdr_t)) {
    // We can only get to this point if our "raw" pocket was larger than the wire header before
    // running the plugins, so this is extremely unlikely outside of either something going really
    // wrong or a targetted attack
    statsd_inc(server->statsd, HE_METRIC_PLUGIN_LENGTH_ERROR, 1);
    return;
  }

  he_wire_hdr_t *hdr = (he_wire_hdr_t *)he_pkt->base;

  // Doesn't have a valid header prefix - reject
  if(hdr->he[0] != 'H' || hdr->he[1] != 'e') {
    return;
  }

  if(!he_ssl_ctx_is_supported_version(server->he_ctx, hdr->major_version, hdr->minor_version)) {
    statsd_inc(server->statsd, HE_METRIC_BAD_PACKET_VERSION, 1);
    return;
  }

  uint64_t session = hdr->session;

  if(session == HE_PACKET_SESSION_REJECT) {
    // Drop this packet to prevent an infinite loop where an attacker causes us to send
    // rejected packets between Helium servers
    return;
  }

  // Create an empty pointer to our client state
  he_server_connection_t *conn = NULL;

  // We might need this later if the IP port combo look up fails but the session is valid
  bool update_connection_address = false;

  // Extract a clean copy of the IP address and port for use as a hashmap key
  // Note: Needs extending for IPv6 support!
  he_v4_ip_port_t ipcombo = he_create_ipcombo_v4_from_addr(addr);

  conn = he_find_connection(server, session, ipcombo, &update_connection_address);

  // If we can't find the connection but the header suggests it exists then
  // send a reject to trigger a client reconnect
  if(!conn && session != HE_PACKET_SESSION_EMPTY) {
    statsd_inc(server->statsd, HE_METRIC_REJECTED_SESSION, 1);
    HE_FLOW_DISPATCH(he_session_reject, &server->udp_socket, addr, dst);
    return;
  }

  // If we can't find the connection but the server is shutting down,
  // then we should tell the client to reconnect to a different server
  if(!conn && server->stopping) {
    statsd_inc(server->statsd, HE_METRIC_REJECTED_SESSION, 1);
    HE_FLOW_DISPATCH(he_session_reject, &server->udp_socket, addr, dst);
    return;
  }

  // If we still haven't found the connection but also have not rejected it then create a fresh
  // connection
  if(!conn) {
    // Creating a new connection can fail. Check that it is successful before continuing
    if((conn = he_create_new_connection(server, addr, dst, ipcombo, hdr->major_version,
                                        hdr->minor_version)) == NULL) {
      return;
    }
    if(!he_ssl_ctx_is_latest_version(server->he_ctx, hdr->major_version, hdr->minor_version)) {
      statsd_inc(server->statsd, HE_METRIC_OLD_PROTOCOL_SESSION, 1);
    }
  }

  // At this point we should have a connection set up...
  res = he_conn_outside_data_received(conn->he_conn, (uint8_t *)he_pkt->base, post_plugin_length);

  if(res != HE_SUCCESS) {
    bool fatal = he_conn_is_error_fatal(conn->he_conn, res);
    he_statistics_report_error(conn, res);

    // Not all errors are fatal, check before terminating the user
    if(fatal) {
      zlogf_time(ZLOG_INFO_LOG_MSG, "Error from libhe: %s (%d)\n", he_return_code_name(res), res);
      he_connection_disconnect(conn);
    }

    return;
  }

  // NOTE: We wait until the first successful WolfSSL decrypt to protect against the case
  // where a crafted packet with a session ID causes us to change the connection IP
  // without verifying the SSL connection first
  if(conn->state->connection_type == HE_CONNECTION_TYPE_DATAGRAM) {
    // Reset age counter
    conn->stats_age_count = 0;

    // If our return IP address and port has changed then update the connection, hashmaps, and
    // trigger a session ID rotation
    if(update_connection_address) {
      // Extract a clean copy of the IP address and port for use as a hashmap key
      // Note: Needs extending for IPv6 support!
      he_v4_ip_port_t ipcombo = he_create_ipcombo_v4_from_addr(addr);

      he_connection_change_of_address(conn, addr, ipcombo);
      update_connection_address = false;
    }

    // Keep the pointer to the udp socket
    conn->last_used_udp_socket = udp_socket;
  }
}

void he_session_reject(uv_udp_t *udp_socket, const struct sockaddr *addr,
                       const struct sockaddr *src) {
  // Session Error identifier
  uint64_t error = HE_PACKET_SESSION_REJECT;
  // Allocate send request
  he_send_req_t *req = (he_send_req_t *)jecalloc(1, sizeof(he_send_req_t));
  HE_CHECK_WITH_MSG(req, "Unable to allocate request");

  // Allocate buffer
  char *write_buf = (char *)jecalloc(1, sizeof(he_wire_hdr_t));
  HE_CHECK_WITH_MSG(write_buf, "Unable to allocate write_buf");

  he_wire_hdr_t *hdr = (he_wire_hdr_t *)write_buf;

  hdr->he[0] = 'H';
  hdr->he[1] = 'e';

  hdr->major_version = 1;
  hdr->minor_version = 0;

  // Memcpy in the session identifier
  memcpy(&hdr->session, &error, sizeof(uint64_t));

  // Initialise the write buffer
  req->buf = uv_buf_init(write_buf, sizeof(he_wire_hdr_t));

  // Write it out
  int err =
      uv_udp_send((uv_udp_send_t *)req, udp_socket, &req->buf, 1, addr, src, on_send_complete);

  if(err) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error occurred during session reject on uv_udp_send: %d\n", err);
  }
}
