#include "plugin_service.h"

#include "util.h"

void he_plugin_init_start(he_server_t *state) {
  if(state->connection_type == HE_CONNECTION_TYPE_DATAGRAM) {
    he_init_plugin_set(state, &state->udp_recv_plugin_set);
  }
}

void he_init_plugin_set(he_server_t *state, he_plugin_set_t *plugin_set) {
  if(!state->fm_server || !state->fm_input || state->fm_server[0] == '\0' ||
     state->fm_input[0] == '\0') {
    return;
  }

  // Only create plugin set for FM1
  if(state->obfuscation_id != 2048) {
    return;
  }

  if(!plugin_set) {
    return;
  }

  plugin_set->plugin_chain = he_plugin_create_chain();
  HE_CHECK_WITH_MSG(plugin_set->plugin_chain, "Unable to allocate a new plugin chain!\n");

  plugin_set->fm_plugin = jecalloc(1, sizeof(plugin_struct_t));
  HE_CHECK_WITH_MSG(plugin_set->fm_plugin, "Unable to allocate a new plugin\n");

  xvpn_obf_engine_plugin(plugin_set->fm_plugin, state->fm_input, state->fm_server, true);

  int res = he_plugin_register_plugin(plugin_set->plugin_chain, plugin_set->fm_plugin);
  HE_CHECK_WITH_MSG(res == HE_SUCCESS, "Unable to register the plugin\n");
}

void he_free_plugin_set(he_plugin_set_t *plugin_set) {
  if (!plugin_set) {
    return;
  }
  xvpn_obf_engine_plugin_free(plugin_set->fm_plugin);
  he_plugin_destroy_chain(plugin_set->plugin_chain);
  jefree(plugin_set->fm_plugin);
  plugin_set->fm_plugin = NULL;
  plugin_set->plugin_chain = NULL;
}

void he_plugin_stop(he_server_t *state) {
  if(state->connection_type == HE_CONNECTION_TYPE_DATAGRAM) {
    he_free_plugin_set(&state->udp_recv_plugin_set);
  }
}
