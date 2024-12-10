#include "hpt_adapter.h"

#include "shared_inside_flow.h"
#include "ip_rewrite.h"
#include "util.h"
#include "statistics.h"
#include "network.h"

void he_hpt_init(he_server_t *state) {
  // Setup the inside write cb
  he_ssl_ctx_set_inside_write_cb(state->he_ctx, hpt_inside_write_cb);

  // Initalise the device
  int res = hpt_init();
  HE_CHECK_WITH_MSG(res == 0, "Fatal Error: Could not find HPT, is the kernel module loaded?\n");

  state->hpt = hpt_alloc(state->tun_device, 8192, on_hpt_packet, state, state->hpt_kthread_idle_usec);

  HE_CHECK_WITH_MSG(state->hpt, "Fatal Error: Could not allocate tun device\n");

  res = uv_poll_init(state->loop, &state->uv_hpt, hpt_wake_fd());

  // Using the full `if` form here to get the uv_strerror
  if(res) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Could not initialise tun interface - %s\n",
               uv_strerror(res));
    zlog_finish();
    exit(EXIT_FAILURE);
  }

  state->uv_hpt.data = state;
}

void he_hpt_start(he_server_t *state) {
  uv_poll_start(&state->uv_hpt, UV_READABLE, on_hpt_event);

  // Now set up the routes
  int res = luaL_dofile(state->L, state->device_setup_script);

  if(res) {
    const char *errmsg = lua_tostring(state->L, -1);
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Cannot load device setup script: %s\n", errmsg);
    zlog_finish();
    exit(EXIT_FAILURE);
  }
}

void on_hpt_event(uv_poll_t *handle, int a, int b) {
  // Get Helium state
  he_server_t *state = (he_server_t *)handle->data;
  HE_CHECK_WITH_MSG(state, "Helium server state not found on tunnel event!\n");
  hpt_drain(state->hpt);
}

// Called by HPT when we call hpt_drain above
void on_hpt_packet(void *handle, uint8_t *msg_content, size_t length) {
  he_server_t *state = (he_server_t *)handle;

  HE_CHECK_WITH_MSG(state, "Helium server not found on HPT packet!\n");

  he_inside_process_packet(state, msg_content, length);
}

he_return_code_t hpt_inside_write_cb(he_conn_t *he_conn, uint8_t *packet, size_t length,
                                     void *context) {
  // Get our context back
  he_server_connection_t *conn = (he_server_connection_t *)context;

// For now just for insight - borrowed from HPT kernel code
#define HPT_RB_ELEMENT_SIZE 2048
#define HPT_RB_ELEMENT_USABLE_SPACE (HPT_RB_ELEMENT_SIZE - sizeof(uint16_t))
  // Drop the packet so HPT doesn't explode
  if(length == 0 || length > HPT_RB_ELEMENT_USABLE_SPACE) {
    // To the logs
    zlogf_time(ZLOG_INFO_LOG_MSG, "Bad packet size of length %d\n", length);
    // We want to report this *every* time it happens (as it never should)
    if(length == 0) {
      // We tried to send an empty packet
      he_statistics_report_metric(conn, HE_METRIC_INVALID_HPT_PACKET_ZERO_SIZE);
    } else {
      // We tried to send an oversized packet
      he_statistics_report_metric(conn, HE_METRIC_INVALID_HPT_PACKET_OVER_SIZED);
    }
    // Either way we can't do anything now so return
    return HE_SUCCESS;
  }

  // If we can't rewrite the ip ignore the error
  he_rewrite_ip_from_client_to_tun_ipv4(conn, packet, length);

  if(conn->state->is_dip_enabled) {
    // Drop the packet if the packet source_ip doesn't match the connection inside_ip
    const ipv4_header_t *ipv4_hdr = (ipv4_header_t *)packet;
    if(conn->inside_ip != ipv4_hdr->src_addr) {
      he_statistics_report_metric(conn, HE_METRIC_INVALID_HPT_PACKET_SPOOFED_INSIDE_IP);

      return HE_SUCCESS;
    }
  }

  // Report stats
  statsd_count(conn->state->statsd, HE_METRIC_INCOMING, length, conn->state->statsd_sample_rate);

  hpt_write(conn->state->hpt, packet, length);

  // We wrote some data reset the data age timer
  conn->data_age_count = 0;

  return HE_SUCCESS;
}
