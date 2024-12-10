#include <helium.h>

#include "client_activities.h"
#include "util.h"

static char *statsd_ca_err = "ca_error";

/**
 * csv format is...
 * "event_type",
 * "client_ip",
 * "username",
 * "common_name",
 * "server_bind_ip",
 * "server_bind_port",
 * "client_platform",
 * "protocol",
 * "obfuscation_id",
 * "ca_version",
 * "xor_value",
 * "bytes_received",
 * "bytes_sent"
 * "assigned_ip"
 */
static const char *template = "%s,%s,%s,%s,%s,%d,%s,%s,%d,2,0,0,0,%s\n";

static const char *he_udp_string = "he-udp";
static const char *he_tcp_string = "he-tcp";

void cleanup_pointers(uv_fs_t *req) {
  // Here we can definitely free the buffer now :-)
  if(req) {
    if(req->data) {
      he_client_activity_t *ca = (he_client_activity_t *)req->data;
      if(ca->buffer.base) {
        jefree(ca->buffer.base);
      }
      jefree(ca);
    }
    uv_fs_req_cleanup(req);
    jefree(req);
  }
}

void on_client_activity_close(uv_fs_t *req) {
  // We can just re-use the request but we need to update the data here
  he_client_activity_t *ca = (he_client_activity_t *)req->data;

  if(req->result < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Failure to close for client activities\n");
    statsd_inc(ca->state->statsd, statsd_ca_err, 1);
    // Unlike the other callbacks we fall through here because we always cleanup
  }
  cleanup_pointers(req);
}

void on_client_activity_chmod(uv_fs_t *req) {
  he_client_activity_t *ca = (he_client_activity_t *)req->data;

  // Report if the write failed
  if(req->result < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Failure to chmod for client activities\n");
    statsd_inc(ca->state->statsd, statsd_ca_err, 1);
    // If chmod failed we still try and close
  }

  // Sync close for testing
  int uv_ret = uv_fs_close(req->loop, req, ca->fd, on_client_activity_close);

  if(uv_ret < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Unable to schedule close for client activities\n");
    statsd_inc(ca->state->statsd, statsd_ca_err, 1);
    cleanup_pointers(req);
    return;  // Not strictly necessary but just in case things get moved around
  }
}

void on_client_activity_write(uv_fs_t *req) {
  // We can just re-use the request but we need to update the data here
  he_client_activity_t *ca = (he_client_activity_t *)req->data;

  if(req->result < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Failure to write for client activities\n");
    statsd_inc(ca->state->statsd, statsd_ca_err, 1);
    cleanup_pointers(req);
    return;
  }

  int write_all = (S_IWUSR | S_IWGRP);
  int read_all = (S_IRUSR | S_IRGRP);
  int uv_ret = uv_fs_fchmod(req->loop, req, ca->fd, read_all | write_all, on_client_activity_chmod);

  if(uv_ret < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Unable schedule chmod for client activities\n");
    statsd_inc(ca->state->statsd, statsd_ca_err, 1);
    cleanup_pointers(req);
    return;  // Not strictly necessary but just in case things get moved around
  }
}

void on_client_activity_mkstemp(uv_fs_t *req) {
  // We can just re-use the request but we need to update the data here
  he_client_activity_t *ca = (he_client_activity_t *)req->data;

  int temp_fd = req->result;

  if(temp_fd < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG,
               "Unable to create temporary file creation for client activities\n");
    statsd_inc(ca->state->statsd, statsd_ca_err, 1);
    cleanup_pointers(req);
    return;
  }

  // In general we can re-use the req handle, but specifically in this callback
  // testing with valgrind confirmed that there is a buffer allocated that becomes
  // "lost" if we don't cleanup immediately.
  uv_fs_req_cleanup(req);

  ca->fd = temp_fd;

  int uv_ret =
      uv_fs_write(ca->state->loop, req, temp_fd, &(ca->buffer), 1, -1, on_client_activity_write);

  if(uv_ret < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Unable to schedule write for client activities\n");
    statsd_inc(ca->state->statsd, statsd_ca_err, 1);
    cleanup_pointers(req);
    return;  // Not strictly necessary but just in case things get moved around
  }
}

he_return_code_t he_schedule_client_activity(he_server_connection_t *conn) {
  uv_fs_t *req = jecalloc(1, sizeof(uv_fs_t));
  HE_CHECK_WITH_MSG(req, "Unable to allocate new fs request");

  he_client_activity_t *ca = jecalloc(1, sizeof(he_client_activity_t));
  HE_CHECK_WITH_MSG(ca, "Unable to allocate new client activity struct");

  ca->state = conn->state;

  char *ca_line = jecalloc(1, 1024);
  HE_CHECK_WITH_MSG(ca_line, "Unable to allocate new output buffer");

  char client_ip[HE_MAX_IPV4_STRING_LENGTH] = {0};
  int2ip(conn->external_ip_port.ip, client_ip, sizeof(client_ip));

  char client_assigned_ip[HE_MAX_IPV4_STRING_LENGTH] = {0};
  int2ip(conn->inside_ip, client_assigned_ip, sizeof(client_assigned_ip));

  const char *protocol_string;
  if(conn->state->connection_type == HE_CONNECTION_TYPE_STREAM) {
    protocol_string = he_tcp_string;

  } else {
    protocol_string = he_udp_string;
  }

  char bind_ip[HE_MAX_IPV4_STRING_LENGTH] = {0};
  if(conn->tcp_is_proxied) {
    int2ip(conn->tcp_proxied_bind_ip_port.ip, bind_ip, sizeof(bind_ip));
  } else {
    safe_strncpy(bind_ip, conn->state->bind_ip, sizeof(bind_ip));
  }

  char *client_platform_id = NULL;
  if(conn->client_platform_id[0]) {
    client_platform_id = conn->client_platform_id;
  } else {
    client_platform_id = "unknown";
  }

  char *username = NULL;
  if(conn->username[0] != '\0') {
    username = conn->username;
  } else {
    // Use hardcoded name for token-based auth
    username = "auth-token-based-user";
  }

  int snprintf_ret = snprintf(ca_line, 1024, template, "on_disconnect", client_ip, username,
                              username, bind_ip, conn->state->bind_port, client_platform_id,
                              protocol_string, conn->state->obfuscation_id, client_assigned_ip);
  HE_CHECK_WITH_MSG((0 < snprintf_ret) && (snprintf_ret < 1024),
                    "Error occurred during snprintf for client_activities\n");

  uv_buf_t iov = uv_buf_init(ca_line, strlen(ca_line));

  ca->buffer = iov;
  req->data = ca;

  int uv_ret =
      uv_fs_mkstemp(conn->state->loop, req, conn->state->ca_tpl, on_client_activity_mkstemp);

  if(uv_ret < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG,
               "Unable to schedule temporary file creation for client activities\n");
    statsd_inc(conn->state->statsd, statsd_ca_err, 1);
    cleanup_pointers(req);
    return HE_ERR_CALLBACK_FAILED;
  }

  return HE_SUCCESS;
}
