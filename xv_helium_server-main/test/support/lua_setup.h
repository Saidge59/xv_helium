#ifndef HE_LUA_SETUP_H
#define HE_LUA_SETUP_H

#include <helium.h>

void lua_setup(he_server_t *server);
void lua_setup_dip(he_server_t *server);

void lua_teardown(he_server_t *server);

#endif  // HE_LUA_SETUP_H
