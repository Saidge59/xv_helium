#include "util.h"
#include <ctype.h>
#include <assert.h>

void alloc_uv_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  // For UDP we allocate additional buffer for RECVMMSG
  // SEE: https://github.com/libuv/libuv/blob/5537d6a689b30039475cf57a0ce8fbbe4d0d9305/src/unix/udp.c#L150-L230
  // For everything else we just use the suggested size
  if (uv_handle_get_type(handle) == UV_UDP && uv_udp_using_recvmmsg((uv_udp_t*)handle)) {
    suggested_size *= 20;
  }
  buf->base = jecalloc(1, suggested_size);
  HE_CHECK_WITH_MSG(buf->base != NULL, "Unable to allocate buffer for incoming data\n");
  // Set the size
  buf->len = suggested_size;
}

void he_lua_init(he_server_t *state) {
  state->L = luaL_newstate();
  luaL_openlibs(state->L);
}

int he_lua_dofile(he_server_t *state, char const *file) {
  return luaL_dofile(state->L, file);
}

void hexdumpraw(void *ptr, char *result, int buflen) {
  unsigned char *buf = (unsigned char *)ptr;
  int a = 0;
  for(a = 0; a < buflen; a++) {
    sprintf(result + (a * 2), "%02X", buf[a]);
  }
}

void hexdump(void *ptr, int buflen) {
  unsigned char *buf = (unsigned char *)ptr;
  int i, j;
  for(i = 0; i < buflen; i += 16) {
    printf("%06x: ", i);
    for(j = 0; j < 16; j++)
      if(i + j < buflen)
        printf("%02x ", buf[i + j]);
      else
        printf("   ");
    printf(" ");
    for(j = 0; j < 16; j++)
      if(i + j < buflen) printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
    printf("\n");
  }
}

/* Convert IP string to 32 bit unsigned int */
uint32_t ip2int(const char *ip) {
  struct in_addr a;
  if(!inet_aton(ip, &a)) {
    // IP was invalid - return 0
    return ((uint32_t)0);
  }
  return a.s_addr;
}

/* Convert 32bit unsigned int to a string representation */
void int2ip(uint32_t ip, char *result, size_t result_size) {
  struct in_addr a;
  a.s_addr = ip;
  inet_ntop(AF_INET, &a, result, result_size);
}

static bool internal_copy_global_lua_string(he_server_t *state, char const *name, char **out) {
  size_t len = 0;
  bool res = (lua_getglobal(state->L, name) == LUA_TSTRING);

  if(res) {
    char const *lua_str_val;
    char *copied_str;

    // LUA will copy the string length into len so we don't need to strlen the string
    lua_str_val = lua_tolstring(state->L, -1, &len);

    HE_CHECK_WITH_MSG(lua_str_val != 0, "Internal LUA failure");

    copied_str = jecalloc(1, len + 1);
    HE_CHECK_WITH_MSG(copied_str, "Unable to allocate string buffer for lua\n");
    memcpy(copied_str, lua_str_val, len);
    copied_str[len] = 0;
    *out = copied_str;
  }
  lua_pop(state->L, -1);
  return res;
}

bool copy_global_lua_int64_array(he_server_t *state, char const *name, int64_t **out,
                                 size_t *length) {
  bool res = (lua_getglobal(state->L, name) == LUA_TTABLE);

  if(res) {
    // Get the number of items in the array
    size_t len = lua_rawlen(state->L, -1);

    if(len > 0) {
      // Prepare buffer for the result
      *out = (int64_t *)jecalloc(len, sizeof(int64_t));
      *length = len;

      for(int i = 0; i < len; i++) {
        // Push the target index to the stack, note that Lua's array index start from 1
        lua_pushinteger(state->L, i + 1);

        // Get the table data at the current index
        lua_gettable(state->L, -2);

        // Check for sentinel nil element
        if(lua_type(state->L, -1) == LUA_TNIL) {
          break;
        }

        // Get the value
        (*out)[i] = (int64_t)luaL_checkinteger(state->L, -1);

        // Pop the stack
        lua_pop(state->L, 1);
      }
    }
  }
  lua_pop(state->L, 1);
  return res;
}

char const *copy_global_lua_string(he_server_t *state, char const *name) {
  char *ret_val = NULL;

  HE_CHECK_WITH_MSG(internal_copy_global_lua_string(state, name, &ret_val),
                    "LUA value is not a string!\n");

  return ret_val;
}

char const *copy_global_lua_string_default(he_server_t *state, char const *name,
                                           char const *default_val) {
  char *ret_val = NULL;

  bool lua_result = internal_copy_global_lua_string(state, name, &ret_val);

  if(!lua_result) {
    if(default_val) {
      size_t len = strlen(default_val);
      char *copy = jecalloc(1, len + 1);
      memcpy(copy, default_val, len);
      ret_val = copy;
    }
  }
  return ret_val;
}

char const *copy_global_lua_string_optional(he_server_t *state, char const *name) {
  char *ret_val = NULL;

  internal_copy_global_lua_string(state, name, &ret_val);

  return ret_val;
}

static bool internal_copy_global_lua_int(he_server_t *state, char const *name, int *out) {
  bool res = (lua_getglobal(state->L, name) == LUA_TNUMBER);

  if(res) {
    *out = lua_tointeger(state->L, -1);
  }
  lua_pop(state->L, 1);
  return res;
}

int copy_global_lua_int(he_server_t *state, char const *name) {
  int result = 0;
  HE_CHECK_WITH_MSG(internal_copy_global_lua_int(state, name, &result),
                    "LUA value is not a number");

  return result;
}

int copy_global_lua_int_default(he_server_t *state, char const *name, int default_val) {
  int result = 0;
  bool lua_result = internal_copy_global_lua_int(state, name, &result);

  if(lua_result) {
    return result;
  } else {
    return default_val;
  }
}

double copy_global_lua_double(he_server_t *state, char const *name) {
  HE_CHECK_WITH_MSG(lua_getglobal(state->L, name) == LUA_TNUMBER, "LUA value is not a number");

  double result = lua_tonumber(state->L, -1);
  lua_pop(state->L, 1);
  return result;
}

static bool internal_copy_global_lua_bool(he_server_t *state, char const *name, bool *out) {
  bool res = (lua_getglobal(state->L, name) == LUA_TBOOLEAN);

  if(res) {
    *out = lua_toboolean(state->L, -1);
  }

  lua_pop(state->L, 1);
  return res;
}

bool copy_global_lua_bool(he_server_t *state, char const *name) {
  bool result;
  HE_CHECK_WITH_MSG(internal_copy_global_lua_bool(state, name, &result),
                    "LUA value is not a boolean");

  return result;
}

bool copy_global_lua_bool_default(he_server_t *state, char const *name, bool default_val) {
  bool result;
  bool lua_result = internal_copy_global_lua_bool(state, name, &result);

  if(lua_result) {
    return result;
  } else {
    return default_val;
  }
}

he_v4_ip_port_t he_create_ipcombo_v4_from_addr(const struct sockaddr *addr) {
  // Extract a clean copy of the IP address and port for use as a hashmap key
  struct sockaddr_in *src_socket = (struct sockaddr_in *)addr;
  he_v4_ip_port_t ipcombo = {0};
  ipcombo.ip = src_socket->sin_addr.s_addr;
  ipcombo.port = src_socket->sin_port;
  return ipcombo;
}

bool he_is_string_valid_alphanum(const char *string_to_test, size_t string_len) {
  if(string_to_test == NULL) {
    return false;
  }
  for(size_t a = 0; a < string_len; a++) {
    // Check for ascii alpha numeric
    if(!isalnum(string_to_test[a])) {
      // If not reject the string
      return false;
    }
  }

  // String looks good
  return true;
}

char *safe_strncpy(char *dst, const char *src, size_t dst_size) {
  assert(NULL != dst && NULL != src && 0 != dst_size);

  char *res = strncpy(dst, src, dst_size - 1);
  dst[dst_size - 1] = '\0';
  return res;
}
