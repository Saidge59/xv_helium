# Helium Server

[![xvpn](https://circleci.com/gh/xvpn/xv_helium_server.svg?style=svg&circle-token=0a1e4b6fd14d52ba13e42d82459bb5e59e2360a0)](https://app.circleci.com/pipelines/github/xvpn/xv_helium_server)

## What is this thing?
[Guided tour of the developer code here.](he_arch.md)

## Command-line Arguments

```console
Usage: helium-server [options]

A light weight high performance VPN server.

    -h, --help            show this help message and exit
    -c, --config=<str>    Location of the server config file

```

## Config File
Helium Server loads the specified config file as lua script on start, then use the following lua global variables to configure the server:

- **auth_script**: Path to a lua script for authenticating users.
- **auth_path**: Path to the sqlite3 database file for authenticating users. This variable is used by the `auth_script` internally. 
- **device_setup_script** Path to a lua script for setting up the tun/hpt device.
- **use_hpt**: (Optional) A boolean indicates whether use the HPT (High-Performance Tun) instead of TUN. Default: `false`.
- **hpt_kthread_idle_usec**: (Optional) Number of microseconds hpt will spin for if idle before sleeping. Default: `0`.
- **tun_device**: Name of the tunnel interface.
- **internal_ip**: CIDR of the internal ip range. Example: `10.125.0.0/16`
- **bind_ip**: The binding ip address of the helium server. Use `0.0.0.0` 
if the helium server needs to listen on all interfaces.
- **bind_port**: The binding port of the helium server.
- **streaming**: (Optional) Use TCP if this boolean variable is set to `true`. Default: `false`.
- **mtu**: An integer specifies the MTU (Maximum Transmission Unit) to be set on the tunnel device.
- **server_cert**: Path to the server certificate in PEM format.
- **server_key**: Path to the server private key.
- **client_ip**: The local ip address to assign to any connected client.
- **peer_ip**: The peer ip address to assign to any connected client.
- **dns_ip**: The dns ip address to assign to any connected client.
- **statsd_ip**: (Optional) A string containing the ip address of the statsd server. Default: `127.0.0.1`
- **statsd_port**: (Optional) A string containing the port the statsd server is listening on. Default: `8125`
- **statsd_namespace**: (Optional) A string containing the namespace for statsd. Default: `helium`
- **statsd_tags**: A string contains the tags for statsd
- **statsd_sample_rate**: A number specifies the sample rate of statsd in seconds.
- **ca_tpl**: A template string (`man 3 mktemp`) for creating the temp directory for client activity data
- **renegotiation_timer_min**: (Optional) A number specifies the renegotiation timer in minutes. Default: `15`
- **no_renegotiation_eviction_timer_hours**: (Optional) A number specifies how many hours the server should wait before evicting a connection since last successful renegotiation. Default: `24`.
- **fm_server**: (Optional) A string contains the `fm_server` value for FM1 obfuscation. Default: `NULL`.
- **fm_input**: (Optional) A string contains the `fm_input` value for FM1 obfuscation. Default: `NULL`.
- **obfuscation_id**: (Optional) A number that specifies the obfuscation id being used. Default: `0`, but if both `fm_input` and `fm_server` is set, the default value of `obfuscation_id` will be `2048` (FM1).
- **post_setup_user**: A string contains the username that the helium server should use when running all post setup scripts.
- **port_scatter**: (Optional) Enable the port scatter feature if this boolean variable is set to `true`. Default: `false`. This setting is only available for UDP.
- **port_scatter_ports**: (Optional) A Lua array contains all available ports for the port scatter feature to use. This setting is only available for UDP and when the `port_scatter` value is set to true.
- **max_socket_queue_size**: (Optional) A number that specifies how large UDP / TCP socket queues can grow to. Default: `15728640 (15 MB)`
- **auth_token_script**: (Optional) Path to a Lua script for authenticating user with token
- **auth_token_public_key_path**: (Optional) Path to the public key file of the auth token
- **auth_token_config**: (Optional) Path to the auth token config file. See https://polymoon.atlassian.net/wiki/spaces/CV/pages/3037757453/Lightway+Token-based+Authentication for details.
- **dip**: (Optional) Boolean to enable DIP mode.
- **dip_ip_allocation_script**: (Optional) Path to a Lua script for Dedicated IP inside ip allocation.
- **dip_internal_ip_map**: (Optional) Path to the Dedicated IP internal IP range mapping. Default: `null`.

### Examples

* Start a UDP server using TUN

```lua
bind_ip = "0.0.0.0"
bind_port = 19655
internal_ip = "10.125"
streaming = false
mtu = 1350
server_cert = "./test/support/server.crt"
server_key  = "./test/support/server.key"
tun_device = "helium-test"
auth_script = "lua/he_auth.lua"
device_setup_script = "lua/he_setup_tun.lua"
auth_path = "./test/support/test_db.sqlite3"

peer_ip = "185.198.242.5"
client_ip = "185.198.242.6"
dns_ip = "8.8.8.8"

statsd_tags = "instance:docker-test"
statsd_sample_rate = 1e-5

ca_tpl = "/tmp/he_ca_XXXXXX"

renegotiation_timer_min = 1

post_setup_user = "openvpn"
```

* Start a TCP server using HPT

```lua
bind_ip = "0.0.0.0"
bind_port = 19655
internal_ip = "10.125"
streaming = true
mtu = 1350
server_cert = "./test/support/server.crt"
server_key  = "./test/support/server.key"
tun_device = "helium-test"
auth_script = "lua/he_auth.lua"
device_setup_script = "lua/he_setup_tun.lua"
auth_path = "./test/support/test_db.sqlite3"
use_hpt = true

peer_ip = "185.198.242.5"
client_ip = "185.198.242.6"
dns_ip = "8.8.8.8"

statsd_tags = "instance:docker-test"
statsd_sample_rate = 1e-5

ca_tpl = "/tmp/he_ca_XXXXXX"

renegotiation_timer_min = 1

post_setup_user = "openvpn"
```

## Metrics
- Each Pleco server runs a [Telegraf](https://github.com/influxdata/telegraf) instance for collecting metrics from different components.
- The Telegraf instance starts a [StatsD](https://github.com/influxdata/telegraf/tree/master/plugins/inputs/statsd) listener service as one of its inputs.
- The StatsD server is [configured](https://github.com/xvpn/xv_pleco_automake/blob/master/etc/templates/telegraf.conf.j2#L15-L32) to run on `localhost:8125`, and the Helium server hardcoded the `127.0.0.1:8125` in its code.
- The Helium server reads the `statsd_tags` field from the config file on start up, and will use the `statsd_tags` without any change as the tags of all stats metrics.

Check [Grafana Cloud](https://expressvpn.grafana.net/explore?orgId=1&left=%7B%22datasource%22:%22grafanacloud-expressvpn-prom%22,%22queries%22:%5B%7B%22refId%22:%22A%22%7D%5D,%22range%22:%7B%22from%22:%22now-1h%22,%22to%22:%22now%22%7D%7D) to explore all metrics send by Helium servers.

To add more tags / labels to the metrics:
- Checkout xv_pleco_automake
- Edit [`etc/templates/helium.conf.j2`](https://github.com/xvpn/xv_pleco_automake/blob/master/etc/templates/helium.conf.j2)
- Add the new label to the `statsd_tags`
- Open a PR and get the change deployed to next Pleco release

## Development (Earthly)

Using Earthly is the simplest way to develop helium server. It runs the builds in docker containers, so you don't have to install anything on your local system.

1. Install Earthly
2. Build

```bash
$ earthly +build
```

3. Run all unit tests

```bash
$ earthly +test
```

4. Create helium server deb package

```bash
$ earthly +build-helium-server
```

## Development (Native)

You can setup your Linux environment to develop helium server natively. This is the most developer friendly method because you can use IDE (e.g. Visual Studio Code) for code completion, checking errors, running tests, etc. 

### Setup the build environment
1. Install developer tools

```bash
$ sudo apt-get -y update
$ sudo apt-get -y install build-essential vim git devscripts debhelper sudo libsqlite3-dev libssl-dev rubygems clang
$ sudo gem install ceedling --no-user-install
```

2. Set environment variables

```bash
$ export CC=clang
$ export CCLD=clang
```

3. Install Earthly

https://earthly.dev/get-earthly

4. Install the build dependencies of helium server

```bash
$ earthly +deps-build-debs
$ sudo apt-get --reinstall --allow-downgrades --allow-change-held-packages -yy install ./artifacts/*.deb
```

5. Install Lua modules which are required by tests

```bash
$ sudo luarocks install lsqlite3
$ sudo luarocks install lua-crypt
$ sudo luarocks install setuid
$ sudo luarocks install inspect
$ cd lua/lua-jwt; sudo luarocks build
```

6. Install Busted and its dependencies for running Lua unit tests

```bash
$ sudo luarocks install busted
```

### Build and Run

1. Build helium-server
   
```bash
$ ceedling release
```

2. Run unit tests

```bash
$ ceedling test
```

3. Set up the `post_setup_user`  
Helium server runs with the user ID of a system user specified as the `post_setup_openvpn` in the conf file.  Most conf files name this user `openvpn`, but modify these instructions accordingly if you use a different name.  
Do this once on your machine to create that system user:  
```bash
$ sudo useradd -r openvpn
```
  
4. Run helium server locally

```bash
$ sudo ./scripts/setup_nat
$ sudo ./build/release/helium-server.out -c test/support/test_server.conf
```

5. Run unit tests of the Lua scripts

```bash
$ cd lua
$ busted
```

## Development (devcontainer)

Using a [devcontainer](https://containers.dev/) allows you to use the
above "native" development flow without installing all the build
dependencies onto your host.

This requires the devcontainer [cli](https://github.com/devcontainers/cli):

```console
$ npm install -g @devcontainers/cli
$ earthly +save-devcontainer
$ devcontainer up --workspace-folder . --remove-existing-container
$ devcontainer exec --workspace-folder . bash
```

At this point you can run `ceedling test` as described in "Development
(Native)" above.

### Setup IDE Environment (Visual Studio Code)

1. Install Extensions:
   - C/C++
   - Ceedling Test Explorer
   - Earthfile Syntax Highlighting

2. Update the C/C++ Extension settings to:

```json
{
    "configurations": [
        {
            "name": "Linux",
            "includePath": [
                "${workspaceFolder}/**"
            ],
            "defines": [],
            "compilerPath": "/usr/bin/clang",
            "cStandard": "c17",
            "cppStandard": "c++14",
            "intelliSenseMode": "linux-clang-x64",
            "compileCommands": "${workspaceFolder}/build/artifacts/compile_commands.json"
        }
    ],
    "version": 4
}
```

## UDP Tuning

Maximum buffer on linux are a bit low and the congestion profile is suboptimal. To tune run these commands on the host (Note: Does not persist between reboots):
```shell
sysctl -w net.core.default_qdisc=fq
sysctl -w net.ipv4.tcp_congestion_control=bbr
sysctl -w net.core.rmem_max=31457280
sysctl -w net.core.wmem_max=31457280
```

For more details see: https://github.com/xvpn/xv_pleco_server/blob/master/modules/common/includes.chroot/etc/sysctl.d/110-xv-networking.conf

## Tag Releases
### Bump debian package version

Every time when you make changes to helium server, remember to bump the debian package version and change log.

Prerequisites:
- `sudo apt install devscripts`

Run:

```bash
$ dch -M -v "version" -D "unstable" -u "low" "Description of the change"
```

Example:

```bash
$ dch -M -v 1.14-1 -D "unstable" -u "low" "Disconnect all connections when receiving SIGTERM"
```

After, commit and push the changes to github and get it merged to `main` branch.

### Create a git tag for the new release

Once the change of debian version and changelog is merged into `main` branch, it's time to create a git tag too. The git tag should be the same as the debian version but with a `v` prefix. For example, if the debian version is `1.14-1`, the git tag should be `v1.14-1`.

Prerequisites:
- `jq` (`sudo apt install jq`)

Run:
- `./scripts/tag-release v1.14-1`

To retrospective tag an old commit, run:
- `COMMIT=<git commit hash> ./scripts/tag-release v1.14-1`
