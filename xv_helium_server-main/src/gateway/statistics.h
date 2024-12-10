#ifndef _STATISTICS_H
#define _STATISTICS_H

#include <helium.h>

/**
 * Initialize the statistics timers for a given state
 */
void he_statistics_init_start(he_server_t *state);

/**
 * If an error occurs this method can be called to report it to metrics.
 */
void he_statistics_report_error(he_server_connection_t *conn, he_return_code_t error_code);

/**
 * Increment the given metric in StatsD
 */
void he_statistics_report_metric(he_server_connection_t *conn, const char *metric);

#endif
