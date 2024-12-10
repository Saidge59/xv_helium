#ifndef LIBHE_TESTABLE_TYPES
#define LIBHE_TESTABLE_TYPES

typedef struct he_ssl_ctx_config {
  int id;
} he_ssl_ctx_config_t;

typedef struct he_ssl_ctx {
  int id;
} he_ssl_ctx_t;

typedef struct he_conn_config {
  int id;
} he_conn_config_t;

typedef struct he_conn {
  int id;
} he_conn_t;

typedef struct he_plugin_chain {
  int id;
} he_plugin_chain_t;

typedef struct hpt {
  int id;
} hpt;

#endif
