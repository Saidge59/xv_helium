_G.internal_ip = "10.125"
_G.tun_device = "helium-test"
_G.mtu = "1350"
_G.post_setup_user = "openvpn"

result = ""
expected = [[
ip tuntap add mode tun dev helium-test
ip link set dev helium-test mtu 1350
ip link set dev helium-test up
ip addr replace 10.125.0.1 peer 10.125.0.2 dev helium-test
ip route replace 10.125.0.0/16 via 10.125.0.2
]]

-- fake the os.execute function
os.execute = function(str)
    result = result .. str .. "\n"
end

-- stub the setuid.setuser function
local setuid = require("setuid")
setuid.setuser = function(str)
    return true
end

describe("loading the he_setup_tun script", function() 
    it("setup tun correctly", function()
        -- clear previous results, ask lua to "forget" ever loading the module
        result = ""
        package.loaded.he_setup_tun = nil

        require("he_setup_tun")
        assert.equals(expected, result)
    end)

    it("setup tun correctly with the new internal_ip format", function()
        _G.internal_ip = "10.125.0.0/16"

        -- clear previous results, ask lua to "forget" ever loading the module
        result = ""
        package.loaded.he_setup_tun = nil

        require("he_setup_tun")
        assert.equals(expected, result)
    end)

    it("setup tun correctly with a non /16 cidr", function()
        _G.internal_ip = "10.127.0.0/24"

        -- clear previous results, ask lua to "forget" ever loading the module
        result = ""
        package.loaded.he_setup_tun = nil

        require("he_setup_tun")
        local expected = [[
ip tuntap add mode tun dev helium-test
ip link set dev helium-test mtu 1350
ip link set dev helium-test up
ip addr replace 10.127.0.1 peer 10.127.0.2 dev helium-test
ip route replace 10.127.0.0/24 via 10.127.0.2
]]
        assert.equals(expected, result)
    end)
end)
