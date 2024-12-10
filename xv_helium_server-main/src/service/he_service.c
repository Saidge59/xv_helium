#include "he_service.h"

#include <msgpack.h>

#include "client_activities.h"
#include "conn_repo.h"
#include "inside_ip_repo.h"
#include "user_repo.h"
#include "tun.h"
#include "util.h"
#include "statistics.h"

void he_service_init(he_server_t *state) {
  // Return code holder for the various functions
  // Note that if we get anything besides success here we just die, no cleanup
  int res = 0;
  // Initialise libhelium
  res = he_init();
  HE_CHECK_WITH_MSG(res == HE_SUCCESS, "Failed to initialise libhelium\n");

  // Set custom memory callbacks for WolfSSL
  he_set_allocators(jemalloc, jecalloc, jerealloc, jefree);

  state->he_ctx = he_ssl_ctx_create();
  HE_CHECK_WITH_MSG(state->he_ctx, "Failed to create SSL context\n");

  res = he_ssl_ctx_set_connection_type(state->he_ctx, state->connection_type);
  HE_CHECK_WITH_MSG(res == HE_SUCCESS, "Failed to set the connection type\n");

  res = he_ssl_ctx_set_server_cert_key_files(state->he_ctx, state->server_cert, state->server_key);
  HE_CHECK_WITH_MSG(res == HE_SUCCESS, "Failed to set the server key path\n");

  he_ssl_ctx_set_auth_cb(state->he_ctx, auth_cb);
  he_ssl_ctx_set_auth_token_cb(state->he_ctx, auth_token_cb);
  he_ssl_ctx_set_auth_buf_cb(state->he_ctx, auth_buf_cb);
  he_ssl_ctx_set_populate_network_config_ipv4_cb(state->he_ctx, populate_network_config_ipv4_cb);
  he_ssl_ctx_set_event_cb(state->he_ctx, server_event_cb);
  he_ssl_ctx_set_state_change_cb(state->he_ctx, state_change_cb);
}

void he_service_start(he_server_t *state) {
  int res = he_ssl_ctx_start_server(state->he_ctx);
  HE_CHECK_WITH_MSG(res == HE_SUCCESS, "Failed to start the server context\n");
}

static bool internal_handle_auth_result(he_server_connection_t *conn, he_auth_type_t auth_type,
                                        bool auth_result) {
  if(auth_result) {
    // Assign inside ip to the connection if necessary
    if(!conn->inside_ip) {
      if(he_assign_inside_ip(conn) != HE_SUCCESS) {
        zlogf_time(ZLOG_INFO_LOG_MSG, "Unable to assign IP, failing auth\n");
        he_statistics_report_metric(conn, HE_METRIC_ASSIGN_INSIDE_IP_ERROR);
        return false;
      }
    }
    // Report auth metric
    switch(auth_type) {
      case HE_AUTH_TYPE_USERPASS:
        he_statistics_report_metric(conn, HE_METRIC_AUTH_SUCCESS_USER_PASS);
        break;
      case HE_AUTH_TYPE_CB:
        he_statistics_report_metric(conn, HE_METRIC_AUTH_SUCCESS_AUTH_BUF);
        break;
      case HE_AUTH_TYPE_TOKEN:
        he_statistics_report_metric(conn, HE_METRIC_AUTH_SUCCESS_AUTH_TOKEN);
        break;
    }
  } else {
    he_statistics_report_metric(conn, HE_METRIC_ACCESS_DENIED);
  }
  return auth_result;
}

bool auth_cb(he_conn_t *he_conn, char const *username, char const *password, void *context) {
  // Get our context back
  he_server_connection_t *conn = (he_server_connection_t *)context;

  bool auth_result = he_check_auth(conn->state, username, password);

  // For buffer auth, we copy the username in conn->username, need to do the same here

  if(auth_result) {
    size_t size = strnlen(username, HE_CONFIG_TEXT_FIELD_LENGTH);
    memcpy(conn->username, username, size);
    conn->username[HE_CONFIG_TEXT_FIELD_LENGTH] = '\0';
  }

  return internal_handle_auth_result(conn, HE_AUTH_TYPE_USERPASS, auth_result);
}

void extract_byte_from_msgpack_object(uint8_t *dest, msgpack_object object) {
  if(dest == NULL) {
    return;
  }

  if(object.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
    return;
  }

  uint64_t val = object.via.u64;
  if(val > UINT8_MAX) {
    return;
  }

  *dest = val;
}

void extract_string_from_msgpack_object(char *dest, msgpack_object object) {
  if(dest == NULL) {
    return;
  }

  if(object.type != MSGPACK_OBJECT_STR) {
    return;
  }

  uint32_t size = object.via.str.size;
  if(size >= HE_CONFIG_TEXT_FIELD_LENGTH) {
    return;
  }

  memcpy(dest, object.via.str.ptr, size);

  dest[size] = '\0';
}

bool auth_token_cb(he_conn_t *he_conn, const uint8_t *token, size_t token_length, void *context) {
  // Get our context back
  he_server_connection_t *conn = (he_server_connection_t *)context;

  bool auth_result = he_check_auth_token(conn, token, token_length);

  if(auth_result) {
    // HACK: Force setting the protocol version to 1.2 when using token based auth, as only the new
    // client will be using auth token. This is a temporary solution until
    // https://polymoon.atlassian.net/browse/LIT-109 is implemented.
    uint8_t protocol_major_version = 1;
    uint8_t protocol_minor_version = 2;
    he_conn_set_protocol_version(conn->he_conn, protocol_major_version, protocol_minor_version);
  }

  return internal_handle_auth_result(conn, HE_AUTH_TYPE_TOKEN, auth_result);
}

bool auth_buf_cb(he_conn_t *he_conn, uint8_t auth_type, uint8_t *buffer, uint16_t length,
                 void *context) {
  // Get our context back
  he_server_connection_t *conn = (he_server_connection_t *)context;

  if(auth_type != AUTH_TYPE_BUF_MSGPACK) {
    return false;
  }

  /* deserialize the buffer into msgpack_object instance. */
  /* deserialized object is valid during the msgpack_zone instance alive. */
  msgpack_zone mempool;
  msgpack_zone_init(&mempool, 2048);

  msgpack_object deserialised = {0};
  msgpack_unpack((const char *)buffer, length, NULL, &mempool, &deserialised);

  /* print the deserialized object. */
  if(deserialised.type != MSGPACK_OBJECT_MAP) {
    msgpack_zone_destroy(&mempool);
    return false;
  }

  char password[HE_CONFIG_TEXT_FIELD_LENGTH + 1] = {0};
  uint8_t protocol_major_version = 0;
  uint8_t protocol_minor_version = 0;

  // Now we know that we have a map so this is safe
  for(msgpack_object_kv *p = deserialised.via.map.ptr;
      p < deserialised.via.map.ptr + deserialised.via.map.size; ++p) {
    msgpack_object key = p->key;

    if(key.type != MSGPACK_OBJECT_STR) {
      continue;
    }

    if(key.via.str.size == 1 && key.via.str.ptr[0] == 'u') {
      extract_string_from_msgpack_object(conn->username, p->val);
    } else if(key.via.str.size == 1 && key.via.str.ptr[0] == 'p') {
      extract_string_from_msgpack_object(password, p->val);
    } else if(key.via.str.size == 2 && key.via.str.ptr[0] == 'c' && key.via.str.ptr[1] == 'p') {
      extract_string_from_msgpack_object(conn->client_platform_id, p->val);
    } else if(key.via.str.size == 2 && key.via.str.ptr[0] == 'p' && key.via.str.ptr[1] == 'M') {
      extract_byte_from_msgpack_object(&protocol_major_version, p->val);
    } else if(key.via.str.size == 2 && key.via.str.ptr[0] == 'p' && key.via.str.ptr[1] == 'm') {
      extract_byte_from_msgpack_object(&protocol_minor_version, p->val);
    }
  }

  // There's no real way to check the minor version, since 0 is a very valid value there
  if(protocol_major_version != 0) {
    he_conn_set_protocol_version(conn->he_conn, protocol_major_version, protocol_minor_version);
  }

  msgpack_zone_destroy(&mempool);

  // Let's not overcheck here, if these are empty we'll just return false

  bool auth_result = he_check_auth(conn->state, conn->username, password);

  return internal_handle_auth_result(conn, HE_AUTH_TYPE_CB, auth_result);
}

he_return_code_t populate_network_config_ipv4_cb(he_conn_t *he_conn,
                                                 he_network_config_ipv4_t *config, void *context) {
  // Get our context back
  he_server_connection_t *conn = (he_server_connection_t *)context;

  // Copy the homogenized network configuration into the auth response
  safe_strncpy(config->local_ip, conn->state->client_ip, sizeof(config->local_ip));
  safe_strncpy(config->peer_ip, conn->state->peer_ip, sizeof(config->peer_ip));
  safe_strncpy(config->dns_ip, conn->state->dns_ip, sizeof(config->dns_ip));

  config->mtu = conn->state->mtu;

  return HE_SUCCESS;
}

he_return_code_t server_event_cb(he_conn_t *he_conn, he_conn_event_t event, void *context) {
  // Get our context back
  he_server_connection_t *conn = (he_server_connection_t *)context;
  switch(event) {
    case HE_EVENT_SECURE_RENEGOTIATION_STARTED:
      he_statistics_report_metric(conn, HE_METRIC_RENEGOTIATION_STARTED);
      break;
    case HE_EVENT_SECURE_RENEGOTIATION_COMPLETED:
      he_statistics_report_metric(conn, HE_METRIC_RENEGOTIATION_COMPLETED);
      break;
    case HE_EVENT_PENDING_SESSION_ACKNOWLEDGED:
      he_finalize_session_id_rotation(conn);
      break;
    default:
      break;
  }
  return HE_SUCCESS;
}

static inline void msgpack_pack_map_uint8(msgpack_packer *pk, const char *key, uint8_t val) {
  assert(pk && key);

  size_t key_len = strnlen(key, HE_CONFIG_TEXT_FIELD_LENGTH);
  msgpack_pack_str(pk, key_len);
  msgpack_pack_str_body(pk, key, key_len);
  msgpack_pack_uint8(pk, val);
}

// Create a msgpack data containing the port scatter server config data, then copy it into the given
// buffer. If the msgpack data is larger than the given buffer provided, no data will be copied.
void he_internal_create_port_scatter_config(he_server_t *state, uint8_t *buf, uint16_t buflen,
                                            uint16_t *outlen) {
  if(state == NULL || !state->port_scatter) {
    return;
  }

  // Count the actual number of scatter ports in use
  size_t count = 0;
  for(int i = 0; i < HE_PORT_SCATTER_MAX_PORTS; i++) {
    if(state->port_scatter_ports[i] > 0) {
      count++;
    }
  }
  if(count == 0) {
    return;
  }

  msgpack_sbuffer sbuf = {0};
  msgpack_packer pk = {0};

  msgpack_sbuffer_init(&sbuf);
  msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

  // A dictionary contains fields "port_scatter_count" and "port_scatter_ports"
  msgpack_pack_map(&pk, 2);

  // port_scatter_count
  msgpack_pack_map_uint8(&pk, "port_scatter_count", count);

  // port_scatter_ports
  const char *key = "port_scatter_ports";
  size_t key_len = strnlen(key, HE_CONFIG_TEXT_FIELD_LENGTH);
  msgpack_pack_str(&pk, key_len);
  msgpack_pack_str_body(&pk, key, key_len);
  msgpack_pack_array(&pk, count);
  for(int i = 0; i < HE_PORT_SCATTER_MAX_PORTS; i++) {
    if(state->port_scatter_ports[i] > 0) {
      msgpack_pack_uint16(&pk, state->port_scatter_ports[i]);
    }
  }

  // Ensure the buffer is big enough to hold the msgpack data
  if(sbuf.size > buflen) {
    goto cleanup;
  }

  // Copy the msgpack data into buffer
  memcpy(buf, sbuf.data, sbuf.size);
  *outlen = sbuf.size;

cleanup:
  msgpack_sbuffer_destroy(&sbuf);
}

he_return_code_t state_change_cb(he_conn_t *he_conn, he_conn_state_t new_state, void *context) {
  // Get our context back
  he_server_connection_t *conn = (he_server_connection_t *)context;

  switch(new_state) {
    case HE_STATE_LINK_UP:
      conn->stats_link_up = uv_hrtime();
      statsd_timing(conn->state->statsd, HE_METRIC_TO_LINK_UP_TIME,
                    HE_NS_TO_MS(conn->stats_link_up - conn->stats_connection_started));

      if(conn->state->port_scatter) {
        // Craft the server config with port information
        uint8_t buffer[HE_MAX_OUTSIDE_MTU] = {0};
        uint16_t length = 0;
        he_internal_create_port_scatter_config(conn->state, buffer, sizeof(buffer), &length);
        if(length > 0) {
          // Aggressively send the server config 3 times in case there's packet loss.
          he_conn_send_server_config(he_conn, buffer, length);
          he_conn_send_server_config(he_conn, buffer, length);
          he_conn_send_server_config(he_conn, buffer, length);
        }
      }

      // Get current cipher and KEM used in the ssl session
      const char *cipher = he_conn_get_current_cipher(he_conn);
      const char *curve = he_conn_get_curve_name(he_conn);
      he_connection_protocol_t protocol = he_conn_get_current_protocol(he_conn);
      zlogf_time(ZLOG_INFO_LOG_MSG, "Session link is up: %zx, cipher: %s, protocol: %d kem: %s\n",
                 he_conn_get_session_id(he_conn), cipher ? cipher : "unknown", protocol,
                 curve ? curve : "unknown");

      // Report link up event to StatsD
      bool use_chacha = (cipher && strstr(cipher, "CHACHA20"));
      if(use_chacha) {
        he_statistics_report_metric(conn, HE_METRIC_LINK_UP_CHACHA20);
      } else {
        he_statistics_report_metric(conn, HE_METRIC_LINK_UP_AES);
      }

      switch(protocol) {
        case HE_CONNECTION_PROTOCOL_TLS_1_3:
          he_statistics_report_metric(conn, HE_METRIC_LINK_UP_TLS_1_3);
          break;
        case HE_CONNECTION_PROTOCOL_DTLS_1_2:
          he_statistics_report_metric(conn, HE_METRIC_LINK_UP_DTLS_1_2);
          break;
        case HE_CONNECTION_PROTOCOL_DTLS_1_3:
          he_statistics_report_metric(conn, HE_METRIC_LINK_UP_DTLS_1_3);
          break;
        default:
          break;
      }

      if(curve) {
        if(strstr(curve, "KYBER")) {
          he_statistics_report_metric(conn, HE_METRIC_LINK_UP_PQC);
        } else if(strstr(curve, "ML_KEM")) {
          he_statistics_report_metric(conn, HE_METRIC_LINK_UP_PQC_ML_KEM);
        } else {
          he_statistics_report_metric(conn, HE_METRIC_LINK_UP_ECC);
        }
      } else {
        he_statistics_report_metric(conn, HE_METRIC_LINK_UP_UNKNOWN_KEM);
      }

      break;
    case HE_STATE_ONLINE:
      he_schedule_client_activity(conn);
      conn->stats_online = uv_hrtime();

      statsd_timing(conn->state->statsd, HE_METRIC_TO_ONLINE_TIME,
                    HE_NS_TO_MS(conn->stats_online - conn->stats_connection_started));
      he_connection_start_renegotiation_timer(conn);

      // Get current protocol version
      uint8_t major_version = 0;
      uint8_t minor_version = 0;
      he_conn_get_protocol_version(conn->he_conn, &major_version, &minor_version);

      // Increment protocol version metrics
      uint16_t version = (major_version << 8) | minor_version;
      switch(version) {
        case 0x0100:
          he_statistics_report_metric(conn, HE_METRIC_ONLINE_WITH_PROTOCOL_V1_0);
          break;
        case 0x0101:
          he_statistics_report_metric(conn, HE_METRIC_ONLINE_WITH_PROTOCOL_V1_1);
          break;
        case 0x0102:
          he_statistics_report_metric(conn, HE_METRIC_ONLINE_WITH_PROTOCOL_V1_2);
          break;
        default:
          he_statistics_report_metric(conn, HE_METRIC_ONLINE_WITH_PROTOCOL_UNKNOWN);
          break;
      }
      break;
    case HE_STATE_DISCONNECTED:
      he_post_disconnect_cleanup(conn);
      break;
    default:
      break;
  }
  return HE_SUCCESS;
}
