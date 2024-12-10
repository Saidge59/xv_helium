#include "statistics.h"

#include "util.h"

#include <assert.h>

static void capture_session_stats(he_server_t *state) {
  // Session counting
  size_t active_5m = 0;
  size_t active_15m = 0;
  size_t active_60m = 0;
  size_t standby_5m = 0;
  size_t standby_15m = 0;
  size_t standby_60m = 0;
  size_t num_sessions = 0;

  // Explore the contents of each bucket
  for(size_t bucket_idx = 0;
      bucket_idx < session_connection_map_num_buckets(&state->connections_by_session);
      bucket_idx++) {
    session_connection_map_bucket_t *bucket = &state->connections_by_session.buckets[bucket_idx];
    for(size_t i = 0; i < session_connection_map_bucket_size(bucket); i++) {
      he_server_connection_t *conn = bucket->data[i].data;
      num_sessions += 1;

      // Ignore connection if not online
      if(!conn->he_conn || he_conn_get_state(conn->he_conn) != HE_STATE_ONLINE) {
        continue;
      }

      // Count sessions that have received data but not outgoing traffic
      if(conn->stats_age_count <= HE_STATS_5M_COUNT && conn->data_age_count > HE_STATS_5M_COUNT) {
        standby_5m++;
      }

      if(conn->stats_age_count <= HE_STATS_15M_COUNT && conn->data_age_count > HE_STATS_15M_COUNT) {
        standby_15m++;
      }

      if(conn->stats_age_count <= HE_STATS_60M_COUNT && conn->data_age_count > HE_STATS_60M_COUNT) {
        standby_60m++;
      }

      // Count sessions that have received outgoing traffic
      if(conn->data_age_count <= HE_STATS_5M_COUNT) {
        active_5m++;
      }

      if(conn->data_age_count <= HE_STATS_15M_COUNT) {
        active_15m++;
      }

      if(conn->data_age_count <= HE_STATS_60M_COUNT) {
        active_60m++;
      }
    }
  }

  // External and assigned IPs count
  size_t inside_ips = ip_connection_map_count(&state->connections_by_inside_ip);
  size_t external_ip_combos =
      ip_port_connection_map_count(&state->connections_by_external_ip_and_port);

  statsd_gauge(state->statsd, "sessions_total", state->stats_session_count);
  statsd_gauge(state->statsd, "sessions_map_count", num_sessions);
  statsd_gauge(state->statsd, "assigned_internal_ips", inside_ips);
  statsd_gauge(state->statsd, "external_ip_map_count", external_ip_combos);

  statsd_gauge(state->statsd, "sessions_active_5m", active_5m);
  statsd_gauge(state->statsd, "sessions_active_15m", active_15m);
  statsd_gauge(state->statsd, "sessions_active_60m", active_60m);

  statsd_gauge(state->statsd, "sessions_standby_5m", standby_5m);
  statsd_gauge(state->statsd, "sessions_standby_15m", standby_15m);
  statsd_gauge(state->statsd, "sessions_standby_60m", standby_60m);
}

static void capture_jemalloc_stats(he_server_t *state) {
  // Update the statistics cached by mallctl.
  uint64_t epoch = 1;
  size_t sz = sizeof(epoch);
  jemallctl("epoch", &epoch, &sz, &epoch, sz);

  // Get basic allocation statistics.
  size_t allocated, active, metadata, resident, mapped;
  sz = sizeof(size_t);
  if(jemallctl("stats.allocated", &allocated, &sz, NULL, 0) == 0 &&
     jemallctl("stats.active", &active, &sz, NULL, 0) == 0 &&
     jemallctl("stats.metadata", &metadata, &sz, NULL, 0) == 0 &&
     jemallctl("stats.resident", &resident, &sz, NULL, 0) == 0 &&
     jemallctl("stats.mapped", &mapped, &sz, NULL, 0) == 0) {
    statsd_gauge(state->statsd, "jemalloc_allocated", allocated);
    statsd_gauge(state->statsd, "jemalloc_active", active);
    statsd_gauge(state->statsd, "jemalloc_metadata", metadata);
    statsd_gauge(state->statsd, "jemalloc_resident", resident);
    statsd_gauge(state->statsd, "jemalloc_mapped", mapped);
  } else {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Unable to obtain jemalloc stats");
  }
}

static void capture_network_stats(he_server_t *state) {
  size_t total_write_queue_size = 0;
  bool is_tcp_server = state->connection_type == HE_CONNECTION_TYPE_STREAM;

  if(is_tcp_server) {
    // Explore the contents of each bucket
    for(size_t bucket_idx = 0;
        bucket_idx < session_connection_map_num_buckets(&state->connections_by_session);
        bucket_idx++) {
      session_connection_map_bucket_t *bucket = &state->connections_by_session.buckets[bucket_idx];
      for(size_t i = 0; i < session_connection_map_bucket_size(bucket); i++) {
        he_server_connection_t *conn = bucket->data[i].data;
        total_write_queue_size +=
            uv_stream_get_write_queue_size((const uv_stream_t *)&conn->tcp_client);
      }
    }
  } else {
    total_write_queue_size += uv_udp_get_send_queue_size(&state->udp_socket);
    if(state->port_scatter) {
      for(int i = 0; i < HE_PORT_SCATTER_MAX_PORTS; i++) {
        uint16_t port = state->port_scatter_ports[i];
        if(port == 0) {
          continue;
        }
        total_write_queue_size += uv_udp_get_send_queue_size(&state->port_scatter_sockets[i]);
      }
    }
  }
  statsd_gauge(state->statsd, "total_write_queue_size", total_write_queue_size);
}

static void on_stats_timer(uv_timer_t *timer) {
  // Grab connection context
  he_server_t *state = (he_server_t *)timer->data;
  HE_CHECK_WITH_MSG(state, "No state supplied in stats timer");

  capture_session_stats(state);
  capture_network_stats(state);
  capture_jemalloc_stats(state);
}

void he_statistics_init_start(he_server_t *state) {
  state->statsd = statsd_init_with_namespace_tags(state->statsd_ip, state->statsd_port,
                                                  state->statsd_namespace, state->statsd_tags);
  uv_timer_init(state->loop, &state->stats_timer);
  state->stats_timer.data = state;
  uv_timer_start(&state->stats_timer, on_stats_timer, HE_TIMER_NOW, HE_TIMER_STATS);
}

void he_statistics_report_metric(he_server_connection_t *conn, const char *metric) {
  assert(conn && conn->state && conn->state->statsd);
  if(!metric) {
    return;
  }

  // Due to the design of statsd-c-client, we must make a copy of the metric string before passing
  // it to statsd library interface
  char metric_copy[HE_METRIC_MAX_LENGTH] = {0};
  safe_strncpy(metric_copy, metric, HE_METRIC_MAX_LENGTH);
  statsd_inc(conn->state->statsd, metric_copy, 1);
}

void he_statistics_report_error(he_server_connection_t *conn, he_return_code_t error_code) {
  bool fatal = he_conn_is_error_fatal(conn->he_conn, error_code);
  int ssl_error = 0;
  char metric_copy[HE_METRIC_MAX_LENGTH] = {0};

  switch(error_code) {
    case HE_SUCCESS:
    case HE_ERR_SERVER_GOODBYE:
      // Specifically ignore these errors
      return;
    case HE_ERR_CONNECTION_WAS_CLOSED:
      snprintf(metric_copy, sizeof(metric_copy), "%s", HE_METRIC_CONN_CLOSED);
      break;
    case HE_ERR_SSL_ERROR:
      ssl_error = he_conn_get_ssl_error(conn->he_conn);
      if(ssl_error != 0) {
        snprintf(metric_copy, sizeof(metric_copy), "%s_%d",
                 (fatal ? HE_METRIC_SSL_ERROR : HE_METRIC_SSL_ERROR_NONFATAL), abs(ssl_error));
      } else {
        snprintf(metric_copy, sizeof(metric_copy), "%s",
                 (fatal ? HE_METRIC_SSL_ERROR : HE_METRIC_SSL_ERROR_NONFATAL));
      }
      break;
    case HE_ERR_SECURE_RENEGOTIATION_ERROR:
      snprintf(metric_copy, sizeof(metric_copy), "%s", HE_METRIC_SECURE_RENEGOTIATION_ERROR);
      break;
    default:
      snprintf(metric_copy, sizeof(metric_copy), "%s_%d",
               (fatal ? HE_METRIC_UNKNOWN_FATAL_ERROR : HE_METRIC_UNKNOWN_NONFATAL_ERROR),
               abs(error_code));
      break;
  }
  statsd_inc(conn->state->statsd, metric_copy, 1);
}
