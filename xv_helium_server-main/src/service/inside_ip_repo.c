#include "inside_ip_repo.h"

#include "key_hash_methods.h"
#include "network.h"
#include "util.h"
#include "statistics.h"

void he_inside_ip_init_start(he_server_t *state) {
  ip_connection_map_init(&state->connections_by_inside_ip);

  // Load the he_dip_ip_allocation.lua script if it's set
  if(state->dip_ip_allocation_script) {
    if(!state->is_dip_enabled) {
      zlogf_time(ZLOG_INFO_LOG_MSG,
                 "Fatal Error: dip_ip_allocation_script provided but DIP not enabled\n");
      zlog_finish();
      exit(EXIT_FAILURE);
    }

    int res = luaL_dofile(state->L, state->dip_ip_allocation_script);
    if(res) {
      const char *errmsg = lua_tostring(state->L, -1);
      zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Cannot load DIP IP allocation script: %s\n",
                 errmsg);
      zlog_finish();
      exit(EXIT_FAILURE);
    }
  }
}

he_return_code_t he_internal_assign_inside_ip(he_server_connection_t *conn) {
  he_return_code_t result_code = HE_ERR_ACCESS_DENIED;

  // Get IP assignment for session by calling LUA method
  if(lua_getglobal(conn->state->L, "allocate_ip") != LUA_TFUNCTION) {
    goto cleanup;
  }

  int res = lua_pcall(conn->state->L, 0, 1, 0);

  if(res != 0) {
    const char *errmsg = lua_tostring(conn->state->L, -1);
    zlogf_time(ZLOG_INFO_LOG_MSG, "Lua error during IP allocation: %s\n", errmsg);
    goto cleanup;
  }

  if(lua_type(conn->state->L, lua_gettop(conn->state->L)) == LUA_TNIL) {
    goto cleanup;
  }

  // Get IP address and store it in the connection
  conn->inside_ip = lua_tointeger(conn->state->L, -1);

  if(!conn->inside_ip) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Lua error during IP allocation: allocate_ip returns 0\n");
    goto cleanup;
  }

  result_code = HE_SUCCESS;

  // Store it in the hash
  ip_connection_map_set(&conn->state->connections_by_inside_ip, conn->inside_ip, conn);

cleanup:
  lua_settop(conn->state->L, 0);
  return result_code;
}

he_return_code_t he_internal_assign_dip_inside_ip(he_server_connection_t *conn, uint32_t dip_u32) {
  he_return_code_t result_code = HE_ERR_ACCESS_DENIED;

  // Get IP assignment for session by calling LUA method
  if(lua_getglobal(conn->state->L, "allocate_dip_ip") != LUA_TFUNCTION) {
    goto cleanup;
  }
  lua_pushinteger(conn->state->L, dip_u32);

  int res = lua_pcall(conn->state->L, 1, 1, 0);
  if(res != 0) {
    const char *errmsg = lua_tostring(conn->state->L, -1);
    zlogf_time(ZLOG_INFO_LOG_MSG, "Lua error calling allocate_dip_ip: %s\n", errmsg);
    goto cleanup;
  }

  if(lua_type(conn->state->L, lua_gettop(conn->state->L)) == LUA_TNIL) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Lua error allocate_dip_ip return nil\n");
    goto cleanup;
  }

  // Get IP address
  conn->inside_ip = lua_tointeger(conn->state->L, -1);

  if(!conn->inside_ip) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Lua error allocate_dip_ip returns 0\n");
    goto cleanup;
  }

  result_code = HE_SUCCESS;

  // Store it in the hash
  ip_connection_map_set(&conn->state->connections_by_inside_ip, conn->inside_ip, conn);

cleanup:
  lua_settop(conn->state->L, 0);
  return result_code;
}

he_return_code_t he_assign_inside_ip(he_server_connection_t *conn) {
  if(conn->state->dip_ip_allocation_script) {
    return he_internal_assign_dip_inside_ip(conn, conn->dip_addr.sin_addr.s_addr);
  } else {
    return he_internal_assign_inside_ip(conn);
  }
}

he_return_code_t he_internal_release_inside_ip(he_server_connection_t *conn) {
  ip_connection_map_remove(&conn->state->connections_by_inside_ip, conn->inside_ip);

  // Release the IP so it can be used again
  lua_getglobal(conn->state->L, "release_ip");
  lua_pushinteger(conn->state->L, conn->inside_ip);
  int res = lua_pcall(conn->state->L, 1, 1, 0);
  if(res != 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "LUA Error: Could not add ip %d back to pool\n", conn->inside_ip);
  }
  conn->inside_ip = 0;

  return res;
}

he_return_code_t he_internal_release_dip_inside_ip(he_server_connection_t *conn) {
  ip_connection_map_remove(&conn->state->connections_by_inside_ip, conn->inside_ip);

  // Release the IP so it can be used again
  lua_getglobal(conn->state->L, "release_dip_ip");
  lua_pushinteger(conn->state->L, conn->dip_addr.sin_addr.s_addr);
  lua_pushinteger(conn->state->L, conn->inside_ip);

  int res = lua_pcall(conn->state->L, 2, 1, 0);
  if(res != 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "LUA Error: Could not add inside ip back to pool\n");
  }

  // Clear the inside ip
  conn->inside_ip = 0;
  return res;
}

he_return_code_t he_release_inside_ip(he_server_connection_t *conn) {
  if(conn->state->dip_ip_allocation_script) {
    return he_internal_release_dip_inside_ip(conn);
  } else {
    return he_internal_release_inside_ip(conn);
  }
}
