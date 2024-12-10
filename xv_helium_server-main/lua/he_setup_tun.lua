require("he_utils")

-- Hacky quick start script to configure server's helium interface
os.execute("ip tuntap add mode tun dev " .. tun_device)
os.execute("ip link set dev " .. tun_device .. " mtu " .. mtu)
os.execute("ip link set dev " .. tun_device .. " up")

local local_ip = get_local_ip_str(internal_ip)
local peer_ip = get_peer_ip_str(internal_ip)
local internal_ip_cidr = get_internal_ip_cidr_str(internal_ip)

os.execute("ip addr replace " .. local_ip .. " peer " .. peer_ip .. " dev " .. tun_device)
os.execute("ip route replace " .. internal_ip_cidr .. " via " .. peer_ip)

local setuid = require("setuid")
assert(setuid.setuser(post_setup_user), "You must create the user specified by 'post_setup_user' in the conf first!")
