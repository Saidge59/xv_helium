#include "state.h"

#include "hpt_adapter.h"
#include "tcp_adapter.h"
#include "tun_adapter.h"
#include "udp_adapter.h"

#include "conn_repo.h"
#include "conn_service.h"
#include "he_service.h"
#include "inside_ip_repo.h"
#include "plugin_service.h"
#include "user_repo.h"

#include "statistics.h"

#include "key_hash_methods.h"
#include "util.h"

/**
 * This logic is responsible for user eviction due to age of revoked credentials
 */
bool connection_age_test(session_connection_map_entry_t *entry) {
  he_server_connection_t *conn = entry->data;
  conn->stats_age_count++;
  conn->absolute_age_count++;
  conn->data_age_count++;
  bool should_expire = conn->stats_age_count >= HE_AGE_TICKS_UNTIL_USER_EXPIRE;
  if(should_expire) {
    he_statistics_report_metric(conn, HE_METRIC_USER_AGED_OUT);
    return should_expire;
  }

  bool old_conn_no_rotation =
      conn->state->connection_type == HE_CONNECTION_TYPE_DATAGRAM &&
      conn->absolute_age_count >= conn->state->ticks_until_no_renegotiation_expiry &&
      !he_conn_supports_renegotiation(conn->he_conn);

  if(old_conn_no_rotation) {
    he_statistics_report_metric(conn, HE_METRIC_USER_EVICTED_NO_RENEGOTIATION);
    return old_conn_no_rotation;
  }

  return false;
}

static bool he_connection_username_is_allowed_vpn_access(session_connection_map_entry_t *entry) {
  he_server_connection_t *conn = (he_server_connection_t *)entry->data;
  bool should_expire = false;

  // Check the username is still valid for the given connection. For token based authentication,
  // since we don't keep the username at all, the connection will stay alive until next server
  // reboot.
  if(conn->username[0] != '\0') {
    should_expire = !he_check_user_is_valid(entry->data->state, conn->username);
  }
  if(should_expire) {
    he_statistics_report_metric(conn, HE_METRIC_USER_EVICTED);
  }
  return should_expire;
}

static void connection_was_expired(session_connection_map_entry_t *entry) {
  he_connection_disconnect(entry->data);
}

static void he_state_on_age_timer(uv_timer_t *timer) {
  // Grab connection context
  he_server_t *state = (he_server_t *)timer->data;
  HE_CHECK_WITH_MSG(state, "No state supplied in age timer");

  session_connection_map_delete_matching(&state->connections_by_session, connection_age_test,
                                         connection_was_expired);
}

static void he_state_on_eviction_timer(uv_timer_t *timer) {
  // Grab connection context
  he_server_t *state = (he_server_t *)timer->data;
  HE_CHECK_WITH_MSG(state, "No state supplied in eviction timer");

  // Evict the connections where the username is no longer valid
  session_connection_map_delete_matching(&state->connections_by_session,
                                         he_connection_username_is_allowed_vpn_access,
                                         connection_was_expired);
}

static void he_state_start_global_timers(he_server_t *state) {
  // Initialize the age timer
  uv_timer_init(state->loop, &state->age_timer);
  state->age_timer.data = state;
  uv_timer_start(&state->age_timer, he_state_on_age_timer, HE_TIMER_AGE, HE_TIMER_AGE);

  // Initialize the eviction timer
  uv_timer_init(state->loop, &state->eviction_timer);
  state->eviction_timer.data = state;
  uv_timer_start(&state->eviction_timer, he_state_on_eviction_timer, HE_EVICTION_TIMER,
                 HE_EVICTION_TIMER);
}

void he_state_load_config(he_server_t *state) {
  // Try to parse the config file
  int res = he_lua_dofile(state, state->config_file);

  if(res) {
    const char *errmsg = lua_tostring(state->L, -1);
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Cannot load config file: %s\n", errmsg);
    zlog_finish();
    exit(EXIT_FAILURE);
  }

  bool streaming;

  // Extract the config
  state->device_setup_script = copy_global_lua_string(state, "device_setup_script");
  state->auth_token_script = copy_global_lua_string_optional(state, "auth_token_script");
  state->auth_token_public_key_path =
      copy_global_lua_string_optional(state, "auth_token_public_key_path");
  state->auth_token_config = copy_global_lua_string_optional(state, "auth_token_config");
  state->use_hpt = copy_global_lua_bool_default(state, "use_hpt", false);
  state->tun_device = copy_global_lua_string(state, "tun_device");
  state->bind_ip = copy_global_lua_string(state, "bind_ip");
  state->bind_port = copy_global_lua_int(state, "bind_port");
  streaming = copy_global_lua_bool_default(state, "streaming", false);
  state->mtu = copy_global_lua_int(state, "mtu");
  state->server_cert = copy_global_lua_string(state, "server_cert");
  state->server_key = copy_global_lua_string(state, "server_key");
  state->statsd_ip = copy_global_lua_string_default(state, "statsd_ip", "127.0.0.1");
  state->statsd_port = copy_global_lua_int_default(state, "statsd_port", 8125);
  state->statsd_namespace = copy_global_lua_string_default(state, "statsd_namespace", "helium");
  state->statsd_tags = copy_global_lua_string(state, "statsd_tags");
  state->statsd_sample_rate = copy_global_lua_double(state, "statsd_sample_rate");
  state->ca_tpl = copy_global_lua_string(state, "ca_tpl");
  state->renegotiation_timer_min =
      copy_global_lua_int_default(state, "renegotiation_timer_min", 15);

  state->dip_ip_allocation_script =
      copy_global_lua_string_optional(state, "dip_ip_allocation_script");
  state->dip_internal_ip_map = copy_global_lua_string_optional(state, "dip_internal_ip_map");
  HE_CHECK_WITH_MSG(!!state->dip_ip_allocation_script == !!state->dip_internal_ip_map,
                    "dip_ip_allocation_script and dip_internal_ip_map must be set simultaneously");

  state->no_renegotiation_eviction_timer_hours =
      copy_global_lua_int_default(state, "no_renegotiation_eviction_timer_hours", 24);

  state->ticks_until_no_renegotiation_expiry =
      state->no_renegotiation_eviction_timer_hours * HE_HOUR_MS / HE_TIMER_AGE;

  // Obfuscation
  state->obfuscation_id = copy_global_lua_int_default(state, "obfuscation_id", 0);
  state->fm_server = copy_global_lua_string_optional(state, "fm_server");
  state->fm_input = copy_global_lua_string_optional(state, "fm_input");
  HE_CHECK_WITH_MSG(!(state->fm_server) == !(state->fm_input),
                    "fm_server and fm_input must be set or not set together\n");
  if(state->fm_server && state->fm_input) {
    if(state->obfuscation_id == 0) {
      // obfuscation_id is not set in config, but both fm_server and fm_input have been set.
      // For backward compatibility, we assume FM1 is used
      state->obfuscation_id = 2048;
    }
  } else {
    HE_CHECK_WITH_MSG(state->obfuscation_id == 0, "incompatible obfuscation id!\n");
  }

  // Append fm_input to statsd_tags if necessary
  if(state->statsd_tags && strstr(state->statsd_tags, "fm_input:") == NULL) {
    char tmp[512] = {0};
    safe_strncpy(tmp, state->statsd_tags, sizeof(tmp));

    // Append a ',' if necessary
    size_t len = strlen(tmp);
    if(len > 0 && tmp[len - 1] != ',') {
      tmp[len] = ',';
      len++;
    }
    HE_CHECK_WITH_MSG(len < sizeof(tmp), "cannot append fm_input to statsd_tags!\n");

    // Append fm_input
    if(state->obfuscation_id > 0) {
      snprintf(&tmp[len], sizeof(tmp) - len, "fm_input:%s,", state->fm_input);
    } else {
      snprintf(&tmp[len], sizeof(tmp) - len, "fm_input:none,");
    }

    // Update state->statsd_tags
    len = strlen(tmp);
    jefree((char *)state->statsd_tags);
    char *statsd_tags = jecalloc(1, len + 1);
    memcpy(statsd_tags, tmp, len);
    state->statsd_tags = statsd_tags;
  }

  if(streaming) {
    state->connection_type = HE_CONNECTION_TYPE_STREAM;
    state->port_scatter = false;  // port scatter is always disabled on TCP

  } else {
    state->connection_type = HE_CONNECTION_TYPE_DATAGRAM;
    state->port_scatter = copy_global_lua_bool_default(state, "port_scatter", false);
    // Default 15MB (inline with OpenVPN)
    state->udp_buffer_size = copy_global_lua_int_default(state, "udp_buffer_size", 15 * MEGABYTE);
    if(state->port_scatter) {
      int64_t *ports = NULL;
      size_t count = 0;
      bool res = copy_global_lua_int64_array(state, "port_scatter_ports", &ports, &count);
      if(res && ports && count > 0) {
        for(int i = 0; i < MIN(count, HE_PORT_SCATTER_MAX_PORTS); i++) {
          int64_t port = ports[i];

          // Check if the port is valid
          if(port < 1024 || port > 65535) {
            port = 0;
          }
          state->port_scatter_ports[i] = (uint16_t)port;
        }
        jefree(ports);
      }
    }
  }

  state->max_socket_queue_size =
      copy_global_lua_int_default(state, "max_socket_queue_size", 15 * 1024 * 1024);

  state->hpt_kthread_idle_usec =
      copy_global_lua_int_default(state, "hpt_kthread_idle_usec", 0);

  state->is_dip_enabled = copy_global_lua_bool_default(state, "dip", false);
  state->auth_script = copy_global_lua_string(state, "auth_script");
  state->auth_path = copy_global_lua_string(state, "auth_path");
  state->internal_ip = copy_global_lua_string(state, "internal_ip");
  state->client_ip = copy_global_lua_string(state, "client_ip");
  state->client_ip_u32 = ip2int(state->client_ip);
  state->peer_ip = copy_global_lua_string(state, "peer_ip");
  state->dns_ip = copy_global_lua_string(state, "dns_ip");

  // Log the config
  zlogf_time(ZLOG_INFO_LOG_MSG, "Server cert:          %s\n", state->server_cert);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Server key:           %s\n", state->server_key);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Listening on:         %s:%d\n", state->bind_ip, state->bind_port);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Streaming Mode:       %s\n", streaming ? "true" : "false");
  zlogf_time(ZLOG_INFO_LOG_MSG, "Internal IP range:    %s\n", state->internal_ip);
  zlogf_time(ZLOG_INFO_LOG_MSG, "HPT Mode:             %s\n", state->use_hpt ? "true" : "false");
  zlogf_time(ZLOG_INFO_LOG_MSG, "HPT kthread idle:     %d\n", state->hpt_kthread_idle_usec);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Tun device:           %s\n", state->tun_device);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Tun MTU:              %d\n", state->mtu);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Auth script:          %s\n", state->auth_script);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Auth path:            %s\n", state->auth_path);
  if(state->auth_token_script) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Auth token script:    %s\n", state->auth_token_script);
    if(state->auth_token_public_key_path) {
      zlogf_time(ZLOG_INFO_LOG_MSG, "Auth token public key path:    %s\n",
                 state->auth_token_public_key_path);
    }
    if(state->auth_token_config) {
      zlogf_time(ZLOG_INFO_LOG_MSG, "Auth token config:    %s\n", state->auth_token_config);
    }
  }
  zlogf_time(ZLOG_INFO_LOG_MSG, "Device script:        %s\n", state->device_setup_script);
  zlogf_time(ZLOG_INFO_LOG_MSG, "statsd ip:            %s\n", state->statsd_ip);
  zlogf_time(ZLOG_INFO_LOG_MSG, "statsd port:          %d\n", state->statsd_port);
  zlogf_time(ZLOG_INFO_LOG_MSG, "statsd namespace:     %s\n", state->statsd_namespace);
  zlogf_time(ZLOG_INFO_LOG_MSG, "statsd tags:          %s\n", state->statsd_tags);
  zlogf_time(ZLOG_INFO_LOG_MSG, "statsd sample rate:   %.1e\n", state->statsd_sample_rate);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Activities Template:  %s\n", state->ca_tpl);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Renegotiation Timer:  %d min\n", state->renegotiation_timer_min);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Reneg Support Timer:  %d hr\n",
             state->no_renegotiation_eviction_timer_hours);
  if(state->fm_server) {
    // We know that fm_input *must* be set here
    zlogf_time(ZLOG_INFO_LOG_MSG, "Obfuscation ID:       %d\n", state->obfuscation_id);
    zlogf_time(ZLOG_INFO_LOG_MSG, "FM Server:            %s\n", state->fm_server);
    zlogf_time(ZLOG_INFO_LOG_MSG, "FM Input:             %s\n", state->fm_input);
  }
  zlogf_time(ZLOG_INFO_LOG_MSG, "Port Scatter:         %s\n",
             state->port_scatter ? "true" : "false");
  zlogf_time(ZLOG_INFO_LOG_MSG, "Max Socket Queue:     %db\n", state->max_socket_queue_size);
  zlogf_time(ZLOG_INFO_LOG_MSG, "DIP:                  %s\n",
             state->is_dip_enabled ? "true" : "false");
}

static void on_tun_closed(uv_handle_t *handle) {
  zlogf_time(ZLOG_INFO_LOG_MSG, "TUN device closed.\n");
}

static void on_udp_closed(uv_handle_t *handle) {
  zlogf_time(ZLOG_INFO_LOG_MSG, "UDP socket closed.\n");
}

static void on_hpt_closed(uv_handle_t *handle) {
  // Get our state back
  he_server_t *state = (he_server_t *)handle->loop->data;

  // Close the hpt file descriptor and shutdown the tun device
  hpt_close(state->hpt);

  zlogf_time(ZLOG_INFO_LOG_MSG, "HPT device closed.\n");
}

void on_he_shutdown_timer(uv_timer_t *timer) {
  // Get our state back
  he_server_t *state = (he_server_t *)timer->loop->data;

  // Close HPT/TUN device
  if(state->use_hpt) {
    uv_close((uv_handle_t *)&state->uv_hpt, on_hpt_closed);
  } else {
    uv_close((uv_handle_t *)&state->uv_tun, on_tun_closed);
  }

  // Close UDP socket
  if(state->connection_type == HE_CONNECTION_TYPE_DATAGRAM) {
    uv_close((uv_handle_t *)&state->udp_socket, on_udp_closed);

    if(state->port_scatter) {
      for(size_t i = 0; i < HE_PORT_SCATTER_MAX_PORTS; i++) {
        if(state->port_scatter_ports[i] > 0) {
          uv_close((uv_handle_t *)&state->port_scatter_sockets[i], on_udp_closed);
        }
      }
    }
  }

  // Close all other libuv handles. They are less important, so we don't set the close_cb callbacks.
  uv_close((uv_handle_t *)&state->shutdown_timer, NULL);
  uv_close((uv_handle_t *)&state->age_timer, NULL);
  uv_close((uv_handle_t *)&state->eviction_timer, NULL);
  uv_close((uv_handle_t *)&state->stats_timer, NULL);
  uv_close((uv_handle_t *)&state->sigterm_handle, NULL);

  // Free plugin memory
  he_plugin_stop(state);

  // Tell the uv_run to return as soon as possible
  uv_stop(timer->loop);
}

void he_state_shutdown(he_server_t *state) {
  // Return directly if the server is already stopping
  if(state->stopping) {
    return;
  }

  zlogf_time(ZLOG_INFO_LOG_MSG, "Shutting down server...\n");

  // Stop accepting new udp connections
  state->stopping = true;

  // Stop accepting new tcp connections
  if(state->connection_type == HE_CONNECTION_TYPE_STREAM) {
    he_tcp_stop(state);
  }

  // Sending Goodbye to all connections
  he_disconnect_all_connections(state);

  // Stop all timers
  uv_timer_stop(&state->age_timer);
  uv_timer_stop(&state->eviction_timer);
  uv_timer_stop(&state->stats_timer);

  // We shouldn't stop the libuv runloop here, because we need it to continue running for a while to
  // send all the goodbye message out. So we start a timer to stop everything and exit after 1s.
  uv_timer_init(state->loop, &state->shutdown_timer);
  uv_timer_start(&state->shutdown_timer, on_he_shutdown_timer, HE_SHUTDOWN_TIMEOUT_MS, 0);
}

static void he_state_handle_sigterm(uv_signal_t *handle, int signum) {
  // Get our context back
  he_server_t *state = (he_server_t *)handle->loop->data;
  he_state_shutdown(state);
}

void he_state_initialize(he_server_t *state) {
  // Initialise libuv
  state->loop = uv_default_loop();

  // Save our context to libuv runloop.
  uv_loop_set_data(state->loop, state);

  // Ignore SIGPIPE because kernel may send the SIGPIPE to the process when syscall write()
  // fails. We want to handle the error ourselves instead of aborting.
  signal(SIGPIPE, SIG_IGN);

  if(0 != uv_signal_init(state->loop, &state->sigterm_handle)) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Could not init uv_signal.\n");
    zlog_finish();
    exit(EXIT_FAILURE);
  }

  // Only trigger cleanup due to SIGTERM once, ignore subsequent SIGTERMs
  if(0 != uv_signal_start(&state->sigterm_handle, &he_state_handle_sigterm, SIGTERM)) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Could not start uv_signal.\n");
    zlog_finish();
    exit(EXIT_FAILURE);
  }

  // Initialise lua primitives
  he_lua_init(state);

  // Load the configuration file at state->config_file
  he_state_load_config(state);

  // Initialize the gateways
  he_statistics_init_start(state);

  // Initialise the non-Helium repos and then services
  he_inside_ip_init_start(state);

  // Initialize connection maps
  he_conn_repo_init_start(state);

  // Init the LUA auth script
  he_user_repo_init_start(state);

  // Setup Helium plugins
  he_plugin_init_start(state);

  // Helium and the Adapters need separate init and start phases, since the adapters set callbacks
  // on the Helium state directly

  // Setup Helium State
  he_service_init(state);

  // Including setting up the callbacks on the ssl ctx config
  if(state->use_hpt) {
    he_hpt_init(state);
  } else {
    he_tun_init(state);
  }

  // Setup network state
  if(state->connection_type == HE_CONNECTION_TYPE_STREAM) {
    he_tcp_init(state);
  } else {
    he_udp_init(state);
  }

  // Setup wolfSSL internal state so that server connections can be created
  he_service_start(state);

  if(state->use_hpt) {
    he_hpt_start(state);
  } else {
    he_tun_start(state);
  }

  if(state->connection_type == HE_CONNECTION_TYPE_STREAM) {
    he_tcp_start(state);
  } else {
    he_udp_start(state);
  }

  // Now that we're running setup our own internal timers
  he_state_start_global_timers(state);
}

void he_state_cleanup(he_server_t *state) {
  if(state->L) {
    lua_close(state->L);
    state->L = NULL;
  }
  jefree((void *)state->server_cert);
  jefree((void *)state->server_key);
  jefree((void *)state->bind_ip);
  jefree((void *)state->internal_ip);
  jefree((void *)state->tun_device);
  jefree((void *)state->auth_script);
  jefree((void *)state->auth_path);
  jefree((void *)state->auth_token_script);
  jefree((void *)state->auth_token_public_key_path);
  jefree((void *)state->auth_token_config);
  jefree((void *)state->auth_token_public_key);
  jefree((void *)state->device_setup_script);
  jefree((void *)state->statsd_ip);
  jefree((void *)state->statsd_namespace);
  jefree((void *)state->statsd_tags);
  jefree((void *)state->ca_tpl);
  jefree((void *)state->fm_server);
  jefree((void *)state->fm_input);
  jefree((void *)state->dip_ip_allocation_script);
  jefree((void *)state->dip_internal_ip_map);
}
