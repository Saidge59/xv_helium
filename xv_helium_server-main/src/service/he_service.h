#ifndef HE_SERVICE_H
#define HE_SERVICE_H

#include <helium.h>

// Strictly following the naming convention would result in these to be he_he_service_* but that
// seems silly -- see rule #1 in he_arch.md
void he_service_init(he_server_t *state);
void he_service_start(he_server_t *state);

// Below are internal functions but exposing them for tests
bool auth_cb(he_conn_t *he_conn, char const *username, char const *password, void *context);
bool auth_buf_cb(he_conn_t *he_conn, uint8_t auth_type, uint8_t *buffer, uint16_t length,
                 void *context);
bool auth_token_cb(he_conn_t *he_conn, const uint8_t *token, size_t token_length, void *context);

he_return_code_t populate_network_config_ipv4_cb(he_conn_t *he_conn,
                                                 he_network_config_ipv4_t *config, void *context);

void he_internal_create_port_scatter_config(he_server_t *state, uint8_t *buf, uint16_t buflen,
                                            uint16_t *outlen);
he_return_code_t server_event_cb(he_conn_t *he_conn, he_conn_event_t event, void *context);
he_return_code_t state_change_cb(he_conn_t *he_conn, he_conn_state_t new_state, void *context);

#endif  // HE_CALLBACKS_H
