#ifndef CLIENT_ACTIVITIES_H
#define CLIENT_ACTIVITIES_H

#include <helium.h>

typedef struct he_client_activity {
  // Temporary file descriptor
  int fd;
  uv_buf_t buffer;
  he_server_t *state;
} he_client_activity_t;

// The only "public" function
he_return_code_t he_schedule_client_activity(he_server_connection_t *conn);

// Callbacks and utility functions exposed for testing
void on_client_activity_close(uv_fs_t *req);
void on_client_activity_chmod(uv_fs_t *req);
void on_client_activity_write(uv_fs_t *req);
void on_client_activity_mkstemp(uv_fs_t *req);
void cleanup_pointers(uv_fs_t *req);

#endif  // CLIENT_ACTIVITIES_H
