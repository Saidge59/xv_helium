#include "tun_adapter.h"

#include "shared_inside_flow.h"
#include "ip_rewrite.h"
#include "tun.h"
#include "util.h"
#include "statistics.h"
#include "network.h"

void he_tun_init(he_server_t *state) {
  // Set up the correct inside write cb
  he_ssl_ctx_set_inside_write_cb(state->he_ctx, tun_inside_write_cb);

  // Initialise the tun device (the actual device is set up in a Lua helper script, but ideally we
  // should do that natively)
  char tundev[IFNAMSIZ];
  safe_strncpy(tundev, state->tun_device, IFNAMSIZ);

  state->tun_fd = tun_alloc(tundev, sizeof(tundev), IFF_TUN | IFF_NO_PI);

  if(state->tun_fd == -1) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Could not allocate tun device '%s'\n", tundev);
    zlog_finish();
    exit(EXIT_FAILURE);
  }

  // Check the tun devices names match - should do but abort if not as the supporting config won't
  // be correct
  if(strncmp(tundev, state->tun_device, IFNAMSIZ)) {
    zlogf_time(ZLOG_INFO_LOG_MSG,
               "Fatal Error: tun device should have been %s but was %s instead!\n",
               state->tun_device, tundev);
    zlog_finish();
    exit(EXIT_FAILURE);
  }

  // Set up the libuv polling handler
  int res = uv_poll_init(state->loop, &state->uv_tun, state->tun_fd);

  if(res) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Could not initialise tun interface - %s\n",
               uv_strerror(res));
    zlog_finish();
    exit(EXIT_FAILURE);
  }

  // Store state on the tun interface
  state->uv_tun.data = state;
}

void he_tun_start(he_server_t *state) {
  // Start listening on the tun interface
  uv_poll_start(&state->uv_tun, UV_READABLE, on_tun_event);

  // Now set up the routes
  int res = luaL_dofile(state->L, state->device_setup_script);

  if(res) {
    const char *errmsg = lua_tostring(state->L, -1);
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Cannot load device setup script: %s\n", errmsg);
    zlog_finish();
    exit(EXIT_FAILURE);
  }
}

void on_tun_event(uv_poll_t *handle, int status, int events) {
  // Get Helium state
  he_server_t *state = (he_server_t *)handle->data;
  HE_CHECK_WITH_MSG(state, "Helium server state not found on tunnel event");

  // What event did we get? We only care about it becoming readable...
  if((events & UV_READABLE) == UV_READABLE) {
    // Loop a maximum of 32 times to prevent thread starvation
    // 32 was chosen as libuv uses the same default for network operations
    // https://github.com/libuv/libuv/blob/5102b2c093681dae2a90ea2196f868de78ec9957/src/unix/udp.c#L229-L232
    for(int i = 0; i < 32; ++i) {
      // Create sizeof(HE_MAX_OUTSIDE_MTU)
      // Read in IP packet

      // This needs to be set to a well understood and used variable - no magic numbers...
      uint8_t msg_content[HE_MAX_OUTSIDE_MTU] = {0};

      // Read a packet
      int length = read_from_tun(handle->io_watcher.fd, msg_content, HE_MAX_OUTSIDE_MTU);

      // Would have blocked, so all packets are read - we can stop reading now
      if(length == -1) {
        return;
      }

      he_inside_process_packet(state, msg_content, length);
    }
  }
}

he_return_code_t tun_inside_write_cb(he_conn_t *he_conn, uint8_t *packet, size_t length,
                                     void *context) {
  // Get our context back
  he_server_connection_t *conn = (he_server_connection_t *)context;

  // If we can't rewrite the ip ignore the error
  he_rewrite_ip_from_client_to_tun_ipv4(conn, packet, length);

  if(conn->state->is_dip_enabled) {
    // Drop the packet if the packet source_ip doesn't match the connection inside_ip
    const ipv4_header_t *ipv4_hdr = (ipv4_header_t *)packet;
    if(conn->inside_ip != ipv4_hdr->src_addr) {
      he_statistics_report_metric(conn, HE_METRIC_INVALID_TUN_PACKET_SPOOFED_INSIDE_IP);

      return HE_SUCCESS;
    }
  }

  // Report stats
  statsd_count(conn->state->statsd, HE_METRIC_INCOMING, length, conn->state->statsd_sample_rate);

  write_to_tun(conn->state->tun_fd, packet, length);

  // We wrote some data reset the data age timer
  conn->data_age_count = 0;

  return HE_SUCCESS;
}
