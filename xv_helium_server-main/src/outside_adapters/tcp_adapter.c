#include "tcp_adapter.h"

#include "conn_service.h"
#include "plugin_service.h"
#include "statistics.h"
#include "util.h"
#include "tcp_proxy.h"

// Public API Starts Here

void he_tcp_init(he_server_t *state) {
  // Set the correct outside_write_cb
  he_ssl_ctx_set_outside_write_cb(state->he_ctx, tcp_write_cb);

  // Setup the TCP sockets
  int res = uv_tcp_init(state->loop, &state->tcp_server);

  if(res) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Cannot initialise TCP socket - %s\n",
               uv_strerror(res));
    zlog_finish();
    HE_EXIT_WITH_FAILURE();
  }

  // Set up IP and port
  struct sockaddr_in recv_addr4 = {0};
  struct sockaddr_in6 recv_addr6 = {0};
  struct sockaddr *recv_addr = NULL;

  // Try parsing the bind_ip as IPv4
  res = uv_ip4_addr(state->bind_ip, state->bind_port, &recv_addr4);
  if(res == 0) {
    recv_addr = (struct sockaddr *)&recv_addr4;
  } else {
    // Try parsing the bind_ip as IPv6
    res = uv_ip6_addr(state->bind_ip, state->bind_port, &recv_addr6);
    if(res) {
      zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Invalid IP address or port - %s\n",
                 uv_strerror(res));
      zlog_finish();
      HE_EXIT_WITH_FAILURE();
    }
    recv_addr = (struct sockaddr *)&recv_addr6;
  }

  // Bind to the ip and port
  res = uv_tcp_bind(&state->tcp_server, recv_addr, 0);
  if(res) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Could not bind TCP server to IP and port - %s\n",
               uv_strerror(res));
    zlog_finish();
    HE_EXIT_WITH_FAILURE();
  }

  // Add global state to the socket for easy lookup
  state->tcp_server.data = state;
}

void he_tcp_start(he_server_t *state) {
  // Start listening for connections
  int res = uv_listen((uv_stream_t *)&state->tcp_server, 128, on_new_streaming_connection);

  if(res) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Could not listen on TCP socket - %s\n",
               uv_strerror(res));
    zlog_finish();
    HE_EXIT_WITH_FAILURE();
  }
}

void he_tcp_stop(he_server_t *state) {
  zlogf_time(ZLOG_INFO_LOG_MSG, "Stopping TCP server...\n");
  uv_close((uv_handle_t *)&state->tcp_server, on_tcp_stopped);
}

// These functions are the outside write callbacks

/**
 * This callback is executed after a packet is sent.
 * It will free all related buffers
 */
void on_send_streaming(uv_write_t *req, int status) {
  write_req_t *send_req = (write_req_t *)req;
  jefree(send_req->buf.base);
  jefree(req);
}

he_return_code_t tcp_write_cb(he_conn_t *he_conn, uint8_t *packet, size_t length, void *context) {
  // Get our context back
  he_server_connection_t *conn = (he_server_connection_t *)context;

  write_req_t *req = (write_req_t *)jecalloc(1, sizeof(write_req_t));
  HE_CHECK_WITH_MSG(req != NULL, "Unable to allocate write request\n");

  // Ensure the output buffer has enough capacity for obfuscation
  size_t capacity = MAX(length * 2, HE_MAX_WIRE_MTU);
  uint8_t *output_buffer = jecalloc(1, capacity);
  HE_CHECK_WITH_MSG(output_buffer != NULL, "Unable to allocate write buffer\n");
  memcpy(output_buffer, packet, length);

#ifdef XV_DEBUG
  zlogf_time(ZLOG_INFO_LOG_MSG, "tcp_write_cb: length = %d\n", length);
  zlog_flush_buffer();
  hexdump(packet, length);
#endif

  size_t post_plugin_length = length;
  he_return_code_t res = he_plugin_egress(conn->tcp_plugin_set.plugin_chain, output_buffer,
                                          &post_plugin_length, capacity);

  if(res != HE_SUCCESS) {
    if(res == HE_ERR_PLUGIN_DROP) {
      res = HE_SUCCESS;
    }
    jefree(output_buffer);
    jefree(req);
    return res;
  }

#ifdef XV_DEBUG
  zlogf_time(ZLOG_INFO_LOG_MSG, "tcp_write_cb: after obfs: length = %d\n", post_plugin_length);
  zlog_flush_buffer();
  hexdump(output_buffer, post_plugin_length);
#endif

  // Setup the request
  req->buf = uv_buf_init((char *)output_buffer, (unsigned int)post_plugin_length);

  int err = uv_write((uv_write_t *)req, (uv_stream_t *)&conn->tcp_client, &req->buf, 1,
                     on_send_streaming);
  if(err) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error occurred during uv_write: %d\n", err);
    on_send_streaming((uv_write_t *)req, err);
    return HE_ERR_CALLBACK_FAILED;
  }

  return HE_SUCCESS;
}

// These are the callback for TCP callbacks

// This callback is called when we start a new connection
void on_new_streaming_connection(uv_stream_t *server, int status) {
  HE_CHECK_WITH_MSG(server, "Impossible state: null stream in on_new_streaming_connection\n");

  he_server_t *he_server = (he_server_t *)server->data;

  if(status < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "New connection error %s\n", uv_strerror(status));
    zlog_flush_buffer();
    return;
  }

  he_server_connection_t *conn = he_create_new_connection_streaming(he_server);
  if(conn == NULL) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Unable to create a new streaming connection\n");
    return;
  }

  status = uv_tcp_init(he_server->loop, &conn->tcp_client);
  if(status != 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Unable to initialise tcp client: %s\n", uv_strerror(status));
    he_connection_disconnect(conn);
    return;
  }
  conn->tcp_client_initialized = true;

  status = uv_accept(server, (uv_stream_t *)&conn->tcp_client);
  // According to the libuv documentation:
  // "When the uv_connection_cb callback is called it is guaranteed that this function will complete
  // successfully the first time. If you attempt to use it more than once, it may fail. It is
  // suggested to only call this function once per uv_connection_cb call."
  //
  // It should be ~impossible to call it more than once, however, we do check for this scenario.
  if(status != 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Unable to accept %s\n", uv_strerror(status));
    he_connection_disconnect(conn);
    return;
  }

  conn->tcp_client.data = conn;

  // Set up DIP address
  if(he_server->is_dip_enabled) {
    if(conn->tcp_is_proxied) {
      conn->dip_addr.sin_family = AF_INET;
      conn->dip_addr.sin_addr.s_addr = conn->tcp_proxied_bind_ip_port.ip;
      conn->dip_addr.sin_port = conn->tcp_proxied_bind_ip_port.port;
    } else {
      int len = sizeof(conn->dip_addr);
      int rc = uv_tcp_getsockname(&conn->tcp_client, (struct sockaddr *)&conn->dip_addr, &len);
      if(rc < 0) {
        zlogf_time(ZLOG_INFO_LOG_MSG, "Unable to obtain client destination ip: %s\n",
                   uv_strerror(rc));
        he_connection_disconnect(conn);
        return;
      }
    }
  }

  // Extract the client IP for client activities
  struct sockaddr_storage peername = {0};
  int namelen = sizeof(peername);

  status = uv_tcp_getpeername(&conn->tcp_client, (struct sockaddr *)&peername, &namelen);
  if(status == 0) {
    if(peername.ss_family == AF_INET) {
      conn->external_ip_port = he_create_ipcombo_v4_from_addr((struct sockaddr *)&peername);
    } else {
      // IPv6 is not supported yet
    }
  } else {
    // Assuming this is NOT fatal
    zlogf_time(ZLOG_INFO_LOG_MSG, "Unable to obtain client IP %s\n", uv_strerror(status));
  }

  status = uv_read_start((uv_stream_t *)&conn->tcp_client, alloc_uv_buffer, on_tcp_read);
  if(status != 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Unable to start read on accepted client%s\n",
               uv_strerror(status));
    he_connection_disconnect(conn);
    return;
  }
}

/**
 * @brief Try getting the proxied address from given buffer as proxy protocol header.
 *
 * @return Return the length of the proxy protocol header. Return 0 if the data is not a valid proxy
 * protocol header,
 */
size_t parse_proxy_addr(uint8_t *buf, size_t size, proxy_addr_t *proxy_addr) {
  // If we don't have enough bytes for the Proxy Protocol Header then bail
  if(size < sizeof(proxy_hdr_v2_t)) {
    // Buffer too small - bounce
    return 0;
  }
  // Overlay proxy protocol header over the buffer
  proxy_hdr_v2_t *hdr = (proxy_hdr_v2_t *)buf;

  // Magic Proxy Protocol bytes to look for
  uint8_t magic_bytes[] = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};

  if(memcmp(hdr->sig, magic_bytes, sizeof(magic_bytes)) != 0) {
    // Didn't find the header
    return 0;
  }

  size_t len = ntohs(hdr->len);
  if(size < sizeof(proxy_hdr_v2_t) + len) {
    // Buffer is too small - bounce
    return 0;
  }

  // Copy the proxy addr
  memcpy(proxy_addr, &buf[sizeof(proxy_hdr_v2_t)], len);

  return sizeof(proxy_hdr_v2_t) + len;
}

// This callback is called with data from the TCP connection
void on_tcp_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
  if(buf == NULL) {
    // Probably not possible but no harm in checking
    return;
  }

  if(client == NULL) {
    // Probably not possible but no harm in checking
    jefree(buf->base);
    return;
  }

  if(nread < 0) {
    if(nread != UV_EOF) {
      zlogf_time(ZLOG_INFO_LOG_MSG, "Read error on tcp socket %s\n", uv_strerror(nread));
    }

    he_server_connection_t *conn = client->data;
    // This will close the connection if not already closed
    he_connection_disconnect(conn);

    jefree(buf->base);
    return;
  }

  // If nread == 0 it's a no-op, just fall through to the cleanup code at the bottom
  if(nread > 0) {
    he_server_connection_t *conn = client->data;

    // Detect PROXY protocol header if it's the first time receiving data from this stream
    size_t proxy_hdr_len = 0;
    if(!conn->tcp_first_byte_seen) {
      proxy_addr_t proxy_addr = {0};
      proxy_hdr_len = parse_proxy_addr((uint8_t *)buf->base, nread, &proxy_addr);
      if(proxy_hdr_len > 0) {
        conn->tcp_is_proxied = true;

        // We've found the proxy protocol header, now save the actual client and bind ip.
        struct sockaddr_in client_addr = {0};
        client_addr.sin_addr.s_addr = proxy_addr.ipv4_addr.src_addr;
        client_addr.sin_port = proxy_addr.ipv4_addr.src_port;
        conn->external_ip_port = he_create_ipcombo_v4_from_addr((struct sockaddr *)&client_addr);

        struct sockaddr_in bind_addr = {0};
        bind_addr.sin_addr.s_addr = proxy_addr.ipv4_addr.dst_addr;
        bind_addr.sin_port = proxy_addr.ipv4_addr.dst_port;
        conn->tcp_proxied_bind_ip_port =
            he_create_ipcombo_v4_from_addr((struct sockaddr *)&bind_addr);
      }
      conn->tcp_first_byte_seen = true;
    }

    // Process Lightway data
    uint8_t *data = (uint8_t *)buf->base + proxy_hdr_len;
    ssize_t data_length = nread - proxy_hdr_len;
    if(data_length > 0) {
      uint64_t on_read_start_time = uv_hrtime();

      HE_FLOW_DISPATCH(he_tcp_outside_stream_received, conn, data, data_length);

      uint64_t on_read_end_time = uv_hrtime();
      statsd_timing_with_sample_rate(conn->state->statsd, HE_METRIC_INCOMING_TIME,
                                     HE_NS_TO_MS(on_read_end_time - on_read_start_time),
                                     conn->state->statsd_sample_rate);
    }
  }

  jefree(buf->base);
}

void on_tcp_stopped(uv_handle_t *server) {
  zlogf_time(ZLOG_INFO_LOG_MSG, "TCP server stopped.\n");
}

void he_tcp_outside_stream_received(he_server_connection_t *conn, uint8_t *data, size_t length) {
  size_t post_plugin_length = length;

#ifdef XV_DEBUG
  zlogf_time(ZLOG_INFO_LOG_MSG, "he_tcp_outside_stream_received: length = %lld\n", length);
  zlog_flush_buffer();
  hexdump(data, length);
#endif

  he_return_code_t res =
      he_plugin_ingress(conn->tcp_plugin_set.plugin_chain, data, &post_plugin_length, length);
  if(res != HE_SUCCESS) {
    if(res != HE_ERR_PLUGIN_DROP) {
      he_statistics_report_metric(conn, HE_METRIC_PLUGIN_ERROR);
    }
    return;
  }

#ifdef XV_DEBUG
  zlogf_time(ZLOG_INFO_LOG_MSG, "he_tcp_outside_stream_received: after obfs: length = %lld\n",
             post_plugin_length);
  zlog_flush_buffer();
  hexdump(data, post_plugin_length);
#endif

  res = he_conn_outside_data_received(conn->he_conn, data, post_plugin_length);
  if(res != HE_SUCCESS) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error from he_conn_outside_data_received: %s (%d)\n",
               he_return_code_name(res), res);
    zlog_flush_buffer();

    bool fatal = he_conn_is_error_fatal(conn->he_conn, res);
    he_statistics_report_error(conn, res);

    // Not all errors are fatal, check before terminating the user
    if(fatal) {
      he_connection_disconnect(conn);
    }

    return;
  }

  // Reset age counter
  conn->stats_age_count = 0;
}
