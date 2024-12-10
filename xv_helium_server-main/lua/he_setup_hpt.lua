require("he_utils")

-- We wait a quick second to make sure the device is up. LUA calls this function so quickly after the ioctl that the device is not actually there
os.execute("sleep 1")

local local_ip = get_local_ip_str(internal_ip)
local peer_ip = get_peer_ip_str(internal_ip)
local internal_ip_cidr = get_internal_ip_cidr_str(internal_ip)

os.execute("ip addr replace " .. local_ip .. " peer " .. peer_ip .. " dev " .. tun_device)
os.execute("ip link set dev " .. tun_device .. " up")
os.execute("ip route replace " .. internal_ip_cidr .. " via " .. peer_ip)

local setuid = require("setuid")
assert(setuid.setuser(post_setup_user), "You must create the user specified by 'post_setup_user' in the conf first!")
