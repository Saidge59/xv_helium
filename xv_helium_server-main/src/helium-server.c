/**
 * External includes
 */
#include <argparse.h>

/**
 * Internal includes
 */
#include "helium.h"
#include "util.h"
#include "state.h"
#include "version.gen.h"

// Create our state
he_server_t state = {0};

int main(int argc, const char **argv) {
  // Initialise logging
  zlog_init_stdout();
  atexit(zlog_finish);

  // Set up the arg parser
  static const char *const usage[] = {"helium-server [options]", NULL};

  struct argparse_option options[] = {
      OPT_HELP(),
      // Set the options to parse -c or config into &state.config_file
      OPT_STRING('c', "config", &state.config_file, "Location of the server config file"),
      // -v --verbose for extra logging
      OPT_BOOLEAN('v', "verbose", &state.verbose, "Enable verbose logging"),
      OPT_END(),
  };

  // Initialise argparser
  struct argparse argparse;
  argparse_init(&argparse, options, usage, 0);
  argparse_describe(&argparse, "\nA light weight high performance VPN server.", "\n");

  // Parse command line options
  argc = argparse_parse(&argparse, argc, argv);

  if(!state.config_file) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Config file required.\n");
    zlog_finish();
    exit(EXIT_FAILURE);
  } else {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Config file: %s\n", state.config_file);
  }

  // Create background thread to flush log buffers
  if(state.verbose) {
    // 10 second flush interval for verbose logging
    zlogf_time(ZLOG_INFO_LOG_MSG, "Verbose logging enabled.\n");
    zlog_init_flush_thread_with_interval(10);
  } else {
    // Use the default flush interval 180 seconds
    zlog_init_flush_thread();
  }

  // Print version strings on start
  zlogf_time(ZLOG_INFO_LOG_MSG, "Server Version:       %s\n", HELIUM_SERVER_VERSION);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Lightway Core:        %s\n", LIGHTWAY_CORE_VERSION);
  zlogf_time(ZLOG_INFO_LOG_MSG, "WolfSSL:              %s\n", WOLFSSL_VERSION);

  // Now that state->config_file is set to the config file path, call he_state_initialize
  he_state_initialize(&state);

  // Flush the logs so far
  zlog_flush_buffer();

  // Run the main loop
  int rc = uv_run(state.loop, UV_RUN_DEFAULT);

  if(rc == 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Server stopped gracefully.\n");
  } else {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Server stopped with errors (rc=%d).\n", rc);
  }

  // Close the runloop and release resources
  uv_loop_close(state.loop);

  // Flush the logs
  zlog_finish();

  // Free up memory allocated inside state
  he_state_cleanup(&state);

  return rc;
}
