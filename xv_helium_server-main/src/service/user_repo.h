#ifndef USER_REPO_H
#define USER_REPO_H

#include <helium.h>

// Internal functions exposed for testing

void he_user_repo_init_start(he_server_t *state);

bool he_check_auth(he_server_t *state, char const *username, char const *password);

bool he_check_auth_token(he_server_connection_t *conn, const uint8_t *token, size_t token_len);

void he_update_auth_token_public_key(he_server_t *state);
void he_load_auth_token_config(he_server_t *state);

/**
 * Check if a username is still valid for auth. Used to decide if a session
 * should be rejected.
 */
bool he_check_user_is_valid(he_server_t *state, char const *username);

#endif  // USER_REPO_H
