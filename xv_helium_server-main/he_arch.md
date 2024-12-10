# xv_helium_server Architecture

## Warning
This document is a constant work-in-progress. Some documentation may be out of date.

## Scope

This document is intended as an introduction to the code in this repository,
focused on providing entry points and refreshers for experienced developers
who haven't seen or have forgotten this repository.

Code comes first -- the goal of this document is to *supplement* and *aid*
reading the code, not to replace it.

## Some Common Naming Conventions

Inside/Outside is very confusing, please read the following carefully.

* "Inside" refers to the packets going to and from the tun device (or our custom "high-performance tunnel"), which on the server-side of the VPN refers to unwrapped packets (with the source IP address field rewritten) sent to public internet services. "Inside" packets are the ones that go from the Helium server to google.com and then back.
* "Outside" refers to the encapsulated, encrypted Lightway packets sent from the Helium server to the Lightway clients.

## Architectural Organisation

The #1 rule of Helium server architecture is "no silly shit". This is an ANSI C library first-and-foremost and the rest of this is intended to be "broad organisational guidelines", not strictly enforced rules.

The Helium Server is roughly organised into a "hexagonal" or "onion" architecture.

The outer layer is composed of the main adapter modules:

Inside Adapters:
* hpt_adapter
* tun_adapter

Outside Adapters:
* tcp_adapter
* udp_adapter

A running Helium server will have one and only one Inside Adapter and Outside Adapter.

The other types of modules are:

Service (Directly alters the server state):
* Connection Repository
* Authentication
* IP Repository

Gateway (Read-only to server state, fire-and-forget to external interfaces):
* Client Activities
* Statistics

Utility (Generally should not access server state):
* Network Functions
* Hash Functions
* Generic Utilities

Primitives:
* UV
* He
* Lua

The *rough* guideline is that our code shouldn't explicitly call *up* this list.

Of course the callback-driven nature of our code means that our code is called a lot by "primitives". If we were writing Java we'd probably have a Helium facade, libuv facade, etc., at a higher level that would isolate the rest of our codebase, but we're not writing Java. See rule #1.


## Life of a Packet

### Incoming: Client -> Internet Flow (UDP - TUN, TCP and HPT work similarly)

1. Helium packet arrives at the UDP socket the server listens to
1. libuv calls the provided `alloc_uv_buffer` callback
1. libuv calls the provided `on_read` callback
1. Inside the `on_read` callback, we check the packet and either lookup the connection or create a new one.
1. We then pass the packet to `he_conn_outside_data_received`.
1. lightway-core processes the packet and *may* unwrap a data packet and call the `inside_write_cb`
1. The `inside_write_cb` rewrites the IP and passes the data to the tun device.

### Outgoing: Internet -> Client Flow

1. Packet arrives at the tunnel device
1. libuv calls `on_tun_event`
1. `on_tun_event` calls `read` on the tun FD and then calls `on_tun_process_ipv4_packet`
1. `on_tun_process_ipv4_packet` uses the packet's destination IP to look up the
   client connection, rewrites the packet so that it will actually get to the client,
   and then calls `he_conn_inside_packet_received`
1. lightway-core processes the packet and *may* then call the `udp_write_cb` with the wrapped data.
1. `udp_write_cb` calls `uv_udp_send`

