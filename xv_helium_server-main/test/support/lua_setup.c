#include "lua_setup.h"

void lua_setup(he_server_t *server) {
  // Initialise Lua
  server->L = luaL_newstate();

  // Load standard libraries
  luaL_openlibs(server->L);

  int res = luaL_dofile(server->L, "test/support/test_lua.conf");
  if(res) {
    const char *errmsg = lua_tostring(server->L, -1);
    fprintf(stderr, "Fatal Error: Cannot load config file: %s\n", errmsg);
    exit(EXIT_FAILURE);
  }

  res = luaL_dofile(server->L, "lua/he_auth.lua");
  if(res) {
    const char *errmsg = lua_tostring(server->L, -1);
    fprintf(stderr, "Fatal Error: Cannot load auth script: %s\n", errmsg);
    exit(EXIT_FAILURE);
  }

  res = luaL_dofile(server->L, "lua/he_auth_token.lua");
  if(res) {
    const char *errmsg = lua_tostring(server->L, -1);
    fprintf(stderr, "Fatal Error: Cannot load auth script: %s\n", errmsg);
    exit(EXIT_FAILURE);
  }
}

void lua_setup_dip(he_server_t *server) {
  int res = luaL_dofile(server->L, "test/support/test_lua_dip.conf");
  if(res) {
    const char *errmsg = lua_tostring(server->L, -1);
    fprintf(stderr, "Fatal Error: Cannot load additional DIP config file: %s\n", errmsg);
    exit(EXIT_FAILURE);
  }

  res = luaL_dofile(server->L, "lua/he_dip_ip_allocation.lua");
  if(res) {
    const char *errmsg = lua_tostring(server->L, -1);
    fprintf(stderr, "Fatal Error: Cannot load DIP IP allocation script: %s\n", errmsg);
    exit(EXIT_FAILURE);
  }
}

void lua_teardown(he_server_t *server) {
  lua_close(server->L);
  server->L = NULL;
}
