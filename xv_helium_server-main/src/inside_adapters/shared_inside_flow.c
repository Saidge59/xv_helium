#include "shared_inside_flow.h"

#include "ip_rewrite.h"
#include "network.h"
#include "util.h"

void he_inside_process_packet(he_server_t *state, uint8_t *msg_content, int length) {
  uint64_t packet_start_time = uv_hrtime();
  // Drop packets which exceed the MTU
  if(length < sizeof(ipv4_header_t) || length > HE_MAX_OUTSIDE_MTU) {
    statsd_count(state->statsd, HE_METRIC_REJECTED_TUN_PACKETS, 1, state->statsd_sample_rate);
  } else {
    switch(he_packet_type(msg_content, length)) {
      case HE_PACKET_IP4: {
        HE_FLOW_DISPATCH(he_inside_lookup_conn, state, msg_content, length);
        break;  // Out of switch
      }
      case HE_PACKET_IP6:
      case HE_BAD_PACKET:
        // Drop ipv6 or bad packets for now
        statsd_count(state->statsd, HE_METRIC_REJECTED_TUN_PACKETS, 1, state->statsd_sample_rate);
        break;  // Out of switch
    }
  }
  // Report stats
  uint64_t packet_end_time = uv_hrtime();
  statsd_timing_with_sample_rate(state->statsd, HE_METRIC_OUTGOING_TIME,
                                 HE_NS_TO_MS(packet_end_time - packet_start_time),
                                 state->statsd_sample_rate);
  statsd_count(state->statsd, HE_METRIC_OUTGOING, length, state->statsd_sample_rate);
}

void he_inside_lookup_conn(he_server_t *state, uint8_t *msg_content, int length) {
  uint32_t dst_ip = he_extract_dst_ip_ipv4(msg_content, length);

  // Find existing connection and drop packet if no known conn
  he_server_connection_t *conn;

  if(!ip_connection_map_find(&state->connections_by_inside_ip, dst_ip, &conn)) {
    statsd_inc(state->statsd, HE_METRIC_REJECTED_TUN_PACKETS, state->statsd_sample_rate);

    return;
  }

  size_t queue_size = 0;

  if(state->connection_type == HE_CONNECTION_TYPE_STREAM) {
    queue_size = uv_stream_get_write_queue_size((const uv_stream_t *)&conn->tcp_client);
  } else {
    // Check the last used socket
    uv_udp_t *udp_socket =
        conn->last_used_udp_socket ? conn->last_used_udp_socket : &state->udp_socket;
    queue_size = uv_udp_get_send_queue_size(udp_socket);
  }

  // Drop the packet if its too large
  if(queue_size + length > state->max_socket_queue_size) {
    return;
  }

  // Rewrite IP header back to values client is expecting
  he_rewrite_ip_from_tun_to_client_ipv4(conn, msg_content, length);

  int res = he_conn_inside_packet_received(conn->he_conn, msg_content, length);

  if(res != HE_SUCCESS) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error returned from libhe for tun packets: %s (%d)",
               he_return_code_name(res), res);
    statsd_inc(state->statsd, HE_METRIC_REJECTED_TUN_PACKETS, state->statsd_sample_rate);
  }
}
