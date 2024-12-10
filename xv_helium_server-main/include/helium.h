#ifndef HE_SERVER
#define HE_SERVER

/**
 * This file is the global include for helium, and bootstraps every structure and define needed.
 * We pull the helium data structures for libhelium (include he.h) and lay out the server specific
 * structures. We also include a set of global server definitions.
 * The file is structured in three sections, INCLUDES, STRUCTURES, and DEFINES (referenced in all
 * caps for search-ability).
 */

/**
 * Begin INCLUDES
 * Headers used globally throughout helium server
 */

// Parts of libhelium essential for dev
#include <he.h>

// General includes
#include <zlog.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <uv.h>

// Hashmap
#include "blhm.h"
#include "key_hash_methods.h"

// StatsD
#include <statsd-client.h>

// High performance tun
#include <hpt/hpt.h>

// tun stuff (needs abstracting)
#include <sys/ioctl.h>

// Lua support
#include <lua5.3/lauxlib.h>
#include <lua5.3/lua.h>
#include <lua5.3/lualib.h>

// JE Malloc
#include <jemalloc.h>

// Obfuscation plugin
#include <xenon/obfuscation_engine.h>

/**
 * End of INCLUDES
 */

/**
 * Beginning of STRUCTURES
 * This section contains all server specific global structures, such as client connections and
 * server state.
 */

// Convenience struct for libuv write requests
// *next is used by uthash
typedef struct write_req {
  uv_write_t req;
  uv_buf_t buf;
  struct write_req *next;
} write_req_t;

// Convenience struct for libuv write requests
// *next is used by uthash
typedef struct he_send_req {
  uv_udp_send_t req;
  uv_buf_t buf;
  struct he_send_req *next;
} he_send_req_t;

// Convience struct to hold all plugins we use
typedef struct he_plugin_set {
  he_plugin_chain_t *plugin_chain;
  plugin_struct_t *fm_plugin;
} he_plugin_set_t;

typedef struct he_server_connection he_server_connection_t;

/**
 * Hash map definitions.
 * These macros create structures for our hash maps
 */

/// These can be refined later, but for now we start with a significant number
/// of buckets (essentially one bucket per client) with a small number of slots
/// in each. We use a prime number here to help ensure a good distribution.
#define NUM_MAP_BUCKETS 16349
#define NUM_SLOTS_STARTING 32

HASH_MAP(ip_connection_map, uint32_t, he_server_connection_t *, ipv4_hash, compare_ipv4,
         NUM_MAP_BUCKETS, NUM_SLOTS_STARTING);
HASH_MAP(ip_port_connection_map, he_v4_ip_port_t, he_server_connection_t *, v4_ip_port_hash,
         compare_v4_ip_port, NUM_MAP_BUCKETS, NUM_SLOTS_STARTING);
HASH_MAP(session_connection_map, uint64_t, he_server_connection_t *, session_id_hash,
         compare_session_id, NUM_MAP_BUCKETS, NUM_SLOTS_STARTING);

/**
 * End of hash map definitions
 */

/**
 * The maximum number of ports can be used for the port scatter feature
 */
#define HE_PORT_SCATTER_MAX_PORTS 20

typedef struct he_server {
  // libuv event loop
  uv_loop_t *loop;

  // libuv signal for handling SIGTERM
  uv_signal_t sigterm_handle;
  uv_timer_t shutdown_timer;

  // libuv server socket
  he_connection_type_t connection_type;

  // Mutually exclusive, one or the other will be NULL based on connection_type
  uv_udp_t udp_socket;
  uv_tcp_t tcp_server;

  // UDP config
  int udp_buffer_size;

  /**
   * The statsd timer reports in to statsd at a fixed interval
   */
  uv_timer_t stats_timer;

  /**
   * The age timer is called frequently and ticks a user's age by its interval.
   * If a user is older than an expiry threshold then it is booted from the session.
   */
  uv_timer_t age_timer;

  /**
   * The eviction timer is used to call an auth eviction routine infrequently.
   * This routine removes expired accounts from the active helium server.
   */
  uv_timer_t eviction_timer;

  /* Tun device stuff */
  int tun_fd;
  uv_poll_t uv_tun;

  /* HPT stuff -- mutually exclusive with the above */
  struct hpt *hpt;
  uv_poll_t uv_hpt;
  uv_timer_t uv_hpt_check;
  // usec hpt kthread is allowed to idle before sleeping
  size_t hpt_kthread_idle_usec;

  /* Lua stuff */
  // Lua state
  lua_State *L;
  /* Config stuff */
  // Location of config file
  char const *config_file;
  // Location of device setup script script (This script adds the IP and sets up routing)
  char const *device_setup_script;
  // Configuration parameter to indicate we should use our HPT or the built-in tun device
  bool use_hpt;
  // Location of the auth script
  char const *auth_script;
  // Auth DB folder path
  char const *auth_path;
  // Location of the auth token script
  char const *auth_token_script;
  // Location of the auth token public key
  char const *auth_token_public_key_path;
  // Location of the auth token config file
  char const *auth_token_config;
  // Cached auth token public key in PEM format
  char *auth_token_public_key;
  // Name of tun device
  char const *tun_device;
  // Internal IP
  char const *internal_ip;
  // Bind IP
  char const *bind_ip;
  // Homogeneous client IP
  // We cache as str and u32 for
  // different procedures
  char const *client_ip;
  uint32_t client_ip_u32;
  // Homogenous peer IP
  char const *peer_ip;
  // Homogenous DNS ip
  char const *dns_ip;
  // Bind Port
  int bind_port;
  // Server certificate location
  char const *server_cert;
  // Server certificate key location
  char const *server_key;
  // Obfuscation ID
  int obfuscation_id;
  // FM Server-specific String
  char const *fm_server;
  // FM Configuration String
  char const *fm_input;
  // Path to the Dedicated IP script
  char const *dip_ip_allocation_script;
  // Path to DIP internal IP map
  char const *dip_internal_ip_map;
  // Dedicated IP
  bool is_dip_enabled;

  // Global hashmaps for connection look up
  ip_connection_map_t connections_by_inside_ip;
  ip_port_connection_map_t connections_by_external_ip_and_port;
  session_connection_map_t connections_by_session;
  session_connection_map_t connections_by_pending_session;

  // StatsD stuff
  statsd_link *statsd;
  char const *statsd_ip;
  int statsd_port;
  char const *statsd_namespace;
  char const *statsd_tags;
  double statsd_sample_rate;
  // Basic session counter
  size_t stats_session_count;

  // Where we write client activities
  char const *ca_tpl;

  // Renegotiation interval in minutes
  int renegotiation_timer_min;

  // No Renegotiation Eviction timer in *hours*
  int no_renegotiation_eviction_timer_hours;

  // Calculated from above
  int ticks_until_no_renegotiation_expiry;

  // libhelium stuff
  he_ssl_ctx_t *he_ctx;

  // Obfuscation Stuff for receiving in UDP mode (global for all users)
  he_plugin_set_t udp_recv_plugin_set;

  // MTU Setting from the configuration file
  int mtu;

  // Indicate the server is stopping
  bool stopping;

  // Verbose logging enabled
  int verbose;

  // Port Scatter enabled
  bool port_scatter;
  uint16_t port_scatter_ports[HE_PORT_SCATTER_MAX_PORTS];
  uv_udp_t port_scatter_sockets[HE_PORT_SCATTER_MAX_PORTS];

  // Maximum size of a socket queue in bytes
  size_t max_socket_queue_size;
} he_server_t;

typedef struct he_server_connection {
  // A pointer to our global state so we can always find it
  he_server_t *state;

  // A pointer to the libhelium connection
  he_conn_t *he_conn;

  // He timer (D/TLS stuff)
  uv_timer_t he_timer;

  // Socket and port of client
  struct sockaddr addr;

  /**
   * A pending session identifier, either HE_PACKET_SESSION_EMPTY or a pending session key.
   *
   * Helium allows session id rotation to avoid session IDs being tracked across disparate
   * connections to networks For example, if we did not re-key then the same session ID would be
   * true whenever connecting to a McBadFoods wifi, giving them stronger features to track you with.
   *
   * Upon a re-key condition (such as changing external IP) the server will issue connections with a
   * new key. This key goes into this 'pending' slot and all messages from the server to the client
   * will be sent with it set as session in he_wire_hdr. The client may choose to accept or reject
   * this new key (by changing their own outbound session ID on he_wire_hdr to the new key upon
   * receiving it). When the client acknowledges that it has accepted the key the server replaces
   * session with the pending ID and clears the pending session id.
   */
  uint64_t pending_session;
  uint64_t cur_session;

  /**
   * The inside_ip is the internal IP address that Helium has assigned this conn.
   *
   * When a conn sends a data packet the packet will be presented to the tunnel device
   * with it's source IP EQUAL TO inside_ip.
   *
   * When a packet is received on the tunnel device Helium will find the conn object
   * with inside_ip EQUAL TO the packet destination IP and forward the packet to
   * that conn.
   *
   */
  uint32_t inside_ip;

  // Client external IP and port
  he_v4_ip_port_t external_ip_port;

  /**
   * The three values below are used to calculate user time statistics.
   * A nanosecond timestamp relative to libUV internal clock.
   * This timestamp CANNOT be converted to time of day.
   */
  uint64_t stats_connection_started;
  uint64_t stats_link_up;
  uint64_t stats_online;

  /**
   * The number of times that the AGE time callback has fired since this user last sent a message
   * via Helium. This counter gets incremented once each time the AGE timer triggers, and reset to 0
   * each time we receive a packet from this conn.
   */
  size_t stats_age_count;

  /**
   * The number of times that the age time callback has fired since this connection was *created*.
   * Unlike the above number, we *never* reset this. We use this to kick off clients who don't
   * support renegotiation periodically
   */
  size_t absolute_age_count;

  /**
   * The number of times that the AGE time callback has fired since this user last sent a data
   * message via Helium. This counter gets incremented once each time the AGE timer triggers, and
   * reset to 0 each time we receive a packet from this conn.
   */
  size_t data_age_count;

  // Renegotiation stuff
  uv_timer_t renegotiation_timer;

  /// Streaming Stuff
  uv_tcp_t tcp_client;
  bool tcp_client_initialized;

  // Obfuscation Stuff when in TCP mode (per-user)
  he_plugin_set_t tcp_plugin_set;

  // Obfuscation Stuff for sending in UDP mode (per-user)
  he_plugin_set_t udp_send_plugin_set;

  // Cached username for client activity
  char username[HE_CONFIG_TEXT_FIELD_LENGTH + 1];

  // Client Platform ID -- an opaque string we pass to client activities
  char client_platform_id[HE_CONFIG_TEXT_FIELD_LENGTH + 1];

  // Pointer to the last udp socket which received packet from this connection.
  // This will be used for sending the response packet to the client. If it's NULL,
  // the default state.udp_socket will be used.
  uv_udp_t *last_used_udp_socket;

  // Set to true if we've already received the first byte from the tcp stream.
  // This flag is used to detect PROXY Protocol Header.
  bool tcp_first_byte_seen;

  // Set to true if the tcp traffic is proxied.
  bool tcp_is_proxied;

  // Set to the actual bind ip if the tcp connection is proxied.
  he_v4_ip_port_t tcp_proxied_bind_ip_port;

  // Destination address of the DIP connection
  struct sockaddr_in dip_addr;
} he_server_connection_t;

/**
 * Beginning of DEFINES
 * This section contains all global definitions for helium server
 */
#define HE_MAX_OUTSIDE_MTU 1500

// We make the buffer size 128kb so that we can use multi-recvmsg support
#define HE_SERVER_BUFFER_SIZE (2 << 16)

// Timer defines
#define HE_SECOND_MS 1000
#define HE_MINUTE_MS (HE_SECOND_MS * 60)
#define HE_HOUR_MS (HE_MINUTE_MS * 60)
#define HE_DAY_MS (HE_HOUR_MS * 24)

#define HE_TIMER_NOW 0
#define HE_TIMER_STATS (HE_SECOND_MS * 30)

/**
 * Frequency of age counter callback
 */
#define HE_TIMER_AGE HE_MINUTE_MS

/**
 * Frequency of the user eviction timer
 * This is expensive since it queries via LUA, so call infrequently.
 */
#define HE_EVICTION_TIMER (6 * HE_HOUR_MS)

/**
 * Number of age timer ticks until we expire a user and reclaim the IP
 */
#define HE_AGE_TICKS_UNTIL_USER_EXPIRE (HE_DAY_MS / HE_TIMER_AGE)

/**
 * Number of age ticks timer before marking inactive for 5, 10, and 15 minutes respectively
 */
#define HE_STATS_5M_COUNT ((HE_MINUTE_MS * 5) / HE_TIMER_AGE)
#define HE_STATS_15M_COUNT ((HE_MINUTE_MS * 15) / HE_TIMER_AGE)
#define HE_STATS_60M_COUNT (HE_HOUR_MS / HE_TIMER_AGE)

/*
 * Unless the client specifies otherwise in the WITH_FRAG msg we fragment by default at 1300 bytes
 */
#define HE_CLIENT_DEFAULT_FRAG_SIZE (1300 - HE_PACKET_OVERHEAD)

/**
 * This is used to work out the correct header offset into buffers for uv_callbacks
 */
#define HE_MSG_SIZE_DELTA_WITH_FRAG sizeof(he_msg_data_with_frag_t) - sizeof(he_msg_data_t)

/**
 * Size of 1MB in bytes for clearer code
 */
#define MEGABYTE (1024 * 1024)

#define AUTH_TYPE_BUF_MSGPACK 23

/**
 * Timeout in milliseconds before stopping the runloop when the server is shutting down
 */
#define HE_SHUTDOWN_TIMEOUT_MS (1 * HE_SECOND_MS)

/**
 * End of DEFINES
 */

#endif
