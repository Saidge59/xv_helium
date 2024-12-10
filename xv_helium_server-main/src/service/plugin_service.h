#ifndef PLUGIN_SERVICE_H
#define PLUGIN_SERVICE_H

#include <helium.h>

void he_plugin_init_start(he_server_t *state);

void he_init_plugin_set(he_server_t *state, he_plugin_set_t *plugin_set);

void he_free_plugin_set(he_plugin_set_t *plugin_set);

void he_plugin_stop(he_server_t *state);

#endif  // PLUGIN_SERVICE_H
