#ifndef CONN_SERVICE_H
#define CONN_SERVICE_H

#include "helium.h"

// What's the difference between this module and conn_repo? Not much! The primary goal of doing so
// was to avoid a "super-module" for connections that had hundreds of lines of code. That being
// said, there is a "soft" split here, and other modules should have to only include one or the
// other.
//
// Service functions:
//   Called directly by adapters and the state
//   Encapsulate orchestration logic across multiple other modules
//
// Repo Functions:
//   Called by other services (except state for init)
//   Have simple logic, often CRUD on the hashmaps or calls to the underlying he connection
//
//
// An indicative example of this split is he_connection_change_of_address (in the service) and
// he_update_connection_address (in the repo); the former coordinates separate operations based on
// the connection types, whereas the latter does the finicky hashmap operations but has little
// "orchestration" logic.

/**
 * @brief Find a connection on the state from either it's IP or the session ID in it's packet
 * header.
 *
 * @return If a connection exists it will be returned, otherwise NULL. If the source IP address or
 * port for a client has changed then the `update_connection_address_out` value will be set to true,
 * otherwise it will be unchanged.
 */
he_server_connection_t *he_find_connection(he_server_t *state, uint64_t session_id,
                                           he_v4_ip_port_t ipcombo,
                                           bool *update_connection_address_out);

/**
 * @brief Given a state, sockaddr, and equivalent ipcombo structure, create a new connection and add
 * it to the state.
 *
 * @param state A pointer to a valid server state.
 * @param addr The source address of the udp packet.
 * @param dst The destination address of the udp packet.
 * @param ipcombo The ip+port combo to be used as the hash key.
 * @param major_version The major protocol version which the client is using.
 * @param minor_version The minor protocol version which the client is using.
 * @return Returns a pointer to the new connection when success, returns NULL otherwise.
 */
he_server_connection_t *he_create_new_connection(he_server_t *state, const struct sockaddr *addr,
                                                 const struct sockaddr *dst,
                                                 he_v4_ip_port_t ipcombo, uint8_t major_version,
                                                 uint8_t minor_version);

/**
 * @brief Create a new TCP connection and add it to the state.
 *
 * @param state A pointer to a valid server state.
 * @return Returns a pointer to the new connection when success, returns NULL otherwise.
 */
he_server_connection_t *he_create_new_connection_streaming(he_server_t *state);

/**
 * @brief Disconnect all current connections.
 *
 * @param state A pointer to a valid server state.
 */
void he_disconnect_all_connections(he_server_t *state);

/**
 * @brief Update a connection when an address changes and begin session ID rotation.
 *
 * @param conn A pointer to a valid connection
 * @param addr The new source address of the udp socket
 * @param ipcombo The ip+port combo to be used as the hash key
 */
void he_connection_change_of_address(he_server_connection_t *conn, const struct sockaddr *addr,
                                     he_v4_ip_port_t ipcombo);

/**
 * @brief Disconnect the given connection and perform necessary cleanups.
 *
 * @param conn A pointer to the connection to be disconnected.
 */
void he_connection_disconnect(he_server_connection_t *conn);

#endif
