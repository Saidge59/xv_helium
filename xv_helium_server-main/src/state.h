#ifndef _STATE_H
#define _STATE_H

#include "helium.h"

/**
 * Initialize timers, signal handlers, auth, maps, for a state
 */
void he_state_initialize(he_server_t *state);

/**
 * @brief Disconnect all connections and shutdown.
 *
 * @param state A pointer to the he_server_t state.
 */
void he_state_shutdown(he_server_t *state);

/**
 * @brief Free up memory allocated inside the he_server_t state.
 *
 * @param state A pointer to the he_server_t state.
 */
void he_state_cleanup(he_server_t *state);

// Internal functions exposed for testing

/**
 * @brief Test if a connection should expire
 *
 * @param entry Pointer to a map entry from a session_connection map
 */
bool connection_age_test(session_connection_map_entry_t *entry);

/**
 * @brief Load the configuration file at state->config_file
 *
 * @param state A pointer to the he_server_t state.
 */
void he_state_load_config(he_server_t *state);

#endif
