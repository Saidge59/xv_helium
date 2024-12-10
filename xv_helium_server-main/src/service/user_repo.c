#include "user_repo.h"

#include "conn_service.h"
#include "util.h"

#include <sys/socket.h>
#include <netinet/in.h>

void he_user_repo_init_start(he_server_t *state) {
  // Load the he_auth.lua script if it's set
  if(state->auth_script) {
    int res = luaL_dofile(state->L, state->auth_script);
    if(res) {
      const char *errmsg = lua_tostring(state->L, -1);
      zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Cannot load auth script: %s\n", errmsg);
      zlog_finish();
      exit(EXIT_FAILURE);
    }
  }

  // Load the he_auth_token.lua script if it's set
  if(state->auth_token_script) {
    int res = luaL_dofile(state->L, state->auth_token_script);
    if(res) {
      const char *errmsg = lua_tostring(state->L, -1);
      zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Cannot load auth token script: %s\n", errmsg);
      zlog_finish();
      exit(EXIT_FAILURE);
    }

    if(state->auth_token_public_key_path) {
      // Load the auth token public key
      he_update_auth_token_public_key(state);
    }

    if(state->auth_token_config) {
      // Load all keys from the auth token config file
      he_load_auth_token_config(state);
    }
  }
}

bool he_check_user_is_valid(he_server_t *state, char const *username) {
  lua_getglobal(state->L, "valid_user");
  lua_pushstring(state->L, username);
  int res = lua_pcall(state->L, 1, 1, 0);
  if(res != 0) {
    // On failure assume the DB is corrupt and let every connected user remain
    // Not logging the username since potential PII
    const char *errmsg = lua_tostring(state->L, -1);
    zlogf_time(ZLOG_INFO_LOG_MSG, "LUA Error: can not decide if user is valid: %s", errmsg);
    return true;
  }

  bool auth_result = lua_toboolean(state->L, -1);
  lua_pop(state->L, 0);

  return auth_result;
}

bool he_check_auth(he_server_t *state, char const *username, char const *password) {
  if((username == NULL) || (password == NULL)) {
    return false;
  }

  size_t username_len = strnlen(username, HE_CONFIG_TEXT_FIELD_LENGTH);
  size_t password_len = strnlen(password, HE_CONFIG_TEXT_FIELD_LENGTH);

  if(!he_is_string_valid_alphanum(username, username_len) ||
     !he_is_string_valid_alphanum(password, password_len)) {
    return false;
  }

  // Push arguments to LUA stack and call auth_user
  // pushlstring takes bounded length, does not need to be NULL terminated
  lua_getglobal(state->L, "auth_user");
  lua_pushlstring(state->L, username, username_len);
  lua_pushlstring(state->L, password, password_len);
  int res = lua_pcall(state->L, 2, 1, 0);

  if(res != 0) {
    const char *errmsg = lua_tostring(state->L, -1);
    zlogf_time(ZLOG_INFO_LOG_MSG, "Lua error during auth: %s\n", errmsg);
    lua_settop(state->L, 0);
    return false;
  }

  // LUA leaves results at the top of the stack
  bool auth_result = lua_toboolean(state->L, -1);
  lua_settop(state->L, 0);

  zlogf_time(ZLOG_INFO_LOG_MSG, "Auth result: %d\n", auth_result);

  return auth_result;
}

void he_load_auth_token_config(he_server_t *state) {
  if(!state->auth_token_config) {
    return;
  }
  lua_getglobal(state->L, "load_all_auth_token_keys");
  lua_pushstring(state->L, state->auth_token_config);
  int res = lua_pcall(state->L, 1, 1, 0);
  if(res != 0) {
    const char *errmsg = lua_tostring(state->L, -1);
    zlogf_time(ZLOG_INFO_LOG_MSG, "LUA Error: cannot load auth token config: %s", errmsg);
    zlog_finish();
    exit(EXIT_FAILURE);
  }
}

// Update the auth token public key and cache it in he_server state.
void he_update_auth_token_public_key(he_server_t *state) {
  // TBD the public key updating process, we could load it from either a disk file or fetch from a
  // url directly, e.g. https://auth.expressvpn.com/pem.
  // Since the public key could be rotated any time on the API side, we also need to design a
  // mechanism to notify the helium-server instance whenever the public key is changed.
  if(!state->auth_token_public_key_path) {
    return;
  }

  // Load the auth token public key from disk.
  FILE *fp = fopen(state->auth_token_public_key_path, "rb");
  if(!fp) {
    zlogf_time(ZLOG_INFO_LOG_MSG,
               "Fatal Error: Cannot open auth token public key file at path: %s!\n",
               state->auth_token_public_key_path);
    zlog_finish();
    exit(EXIT_FAILURE);
  }

  // Read the whole file into memory
  fseek(fp, 0, SEEK_END);
  size_t len = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  if(len > 4096) {
    // The file size is too large for a public key pem
    fclose(fp);
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: public key file is too large: %s!\n",
               state->auth_token_public_key_path);
    zlog_finish();
    exit(EXIT_FAILURE);
  }

  // Free the cached public key first
  if(state->auth_token_public_key) {
    jefree((void *)state->auth_token_public_key);
    state->auth_token_public_key = NULL;
  }

  // Read the key into memory
  state->auth_token_public_key = jecalloc(1, len);
  size_t n = fread(state->auth_token_public_key, len, 1, fp);
  if(n != 1) {
    // Error while reading from the file
    fclose(fp);
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: error while reading the public key file: rc=%d!\n",
               n);
    zlog_finish();
    exit(EXIT_FAILURE);
  }

  // Clean up
  fclose(fp);
}

bool he_check_auth_token(he_server_connection_t *conn, const uint8_t *token, size_t token_len) {
  // This should never happen, but we check it anyway
  if(conn == NULL || conn->state == NULL || token == NULL || token_len == 0) {
    return false;
  }

  he_server_t *state = conn->state;
  int res = 0;

  // Push arguments to LUA stack and call auth_user
  // pushlstring takes bounded length, does not need to be NULL terminated

  if(state->is_dip_enabled) {
    // Get the destination ip of current connection
    char dst_ip_str[HE_MAX_IPV4_STRING_LENGTH] = {0};
    int2ip(conn->dip_addr.sin_addr.s_addr, dst_ip_str, sizeof(dst_ip_str));
    // Call auth_user_with_dip_token and set the connection's destination ip
    lua_getglobal(state->L, "auth_user_with_dip_token");
    lua_pushlstring(state->L, (const char *)token, token_len);
    lua_pushlstring(state->L, (const char *)dst_ip_str, strlen(dst_ip_str));
    res = lua_pcall(state->L, 2, 2, 0);
  } else {
    if(state->auth_token_public_key) {
      // Call auth_user_with_token_and_key function with default leeway
      lua_getglobal(state->L, "auth_user_with_token_and_key");
      lua_pushlstring(state->L, (const char *)token, token_len);
      lua_pushstring(state->L, state->auth_token_public_key);
      res = lua_pcall(state->L, 2, 2, 0);
    } else {
      // Call auth_user_with_token using default options
      lua_getglobal(state->L, "auth_user_with_token");
      lua_pushlstring(state->L, (const char *)token, token_len);
      res = lua_pcall(state->L, 1, 2, 0);
    }
  }

  if(res != 0) {
    const char *errmsg = lua_tostring(state->L, -1);
    zlogf_time(ZLOG_INFO_LOG_MSG, "Lua error during auth: %s\n", errmsg);
    zlog_flush_buffer();
    lua_settop(state->L, 0);
    return false;
  }

  // Lua auth token functions always return 2 values
  const char *errmsg = lua_tostring(state->L, -1);
  bool auth_result = lua_toboolean(state->L, -2);

  if(auth_result) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Auth success!\n");
  } else {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Auth error: %s\n", errmsg);
  }
  lua_settop(state->L, 0);
  zlog_flush_buffer();

  return auth_result;
}
