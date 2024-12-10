#ifndef IP_REPO_H
#define IP_REPO_H

#include <helium.h>

void he_inside_ip_init_start(he_server_t *state);

/**
 * Allocate an IP and assign it to the provided connection.
 * returns HE_SUCCESS if successful, any other result indicates error.
 */
he_return_code_t he_assign_inside_ip(he_server_connection_t *conn);

he_return_code_t he_release_inside_ip(he_server_connection_t *conn);

he_return_code_t he_internal_assign_dip_inside_ip(he_server_connection_t *conn, uint32_t dip_u32);

#endif  // IP_REPO_H
