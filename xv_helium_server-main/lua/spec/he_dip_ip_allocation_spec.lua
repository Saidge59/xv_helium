-- Import the script for testing
_G.dip_internal_ip_map = "support/dip_internal_ip_map.json"

require("he_dip_ip_allocation")

describe('init_dip_internal_ip_map', function()
   it('should return the expected pools', function()
      local pools = init_dip_internal_ip_map()
      assert.is_not_nil(pools)
      assert.are.equals(16, #pools[ip2int("192.168.220.202")])
      assert.are.equals(16, #pools[ip2int("192.168.220.203")])
      assert.are.equals(16, #pools[ip2int("192.168.220.204")])
   end)
end)

describe('global_dip_ip_pools', function()
   it('should assign from the expected pool', function()
      _G.free_dip_internal_ips = init_dip_internal_ip_map()

      local local_ip202 = allocate_dip_ip(ip2int("192.168.220.202"))
      assert.are.equals(ip2int("10.125.0.31"), local_ip202)
      assert.are.equals(15, #_G.free_dip_internal_ips[ip2int("192.168.220.202")])
      assert.are.equals(16, #_G.free_dip_internal_ips[ip2int("192.168.220.203")])
      assert.are.equals(16, #_G.free_dip_internal_ips[ip2int("192.168.220.204")])

      local local_ip203 = allocate_dip_ip(ip2int("192.168.220.203"))
      assert.are.equals(ip2int("10.125.0.47"), local_ip203)
      assert.are.equals(15, #_G.free_dip_internal_ips[ip2int("192.168.220.202")])
      assert.are.equals(15, #_G.free_dip_internal_ips[ip2int("192.168.220.203")])
      assert.are.equals(16, #_G.free_dip_internal_ips[ip2int("192.168.220.204")])

      release_dip_ip(ip2int("192.168.220.202"), local_ip202)
      assert.are.equals(16, #_G.free_dip_internal_ips[ip2int("192.168.220.202")])
      assert.are.equals(15, #_G.free_dip_internal_ips[ip2int("192.168.220.203")])
      assert.are.equals(16, #_G.free_dip_internal_ips[ip2int("192.168.220.204")])

      release_dip_ip(ip2int("192.168.220.203"), local_ip203)
      assert.are.equals(16, #_G.free_dip_internal_ips[ip2int("192.168.220.202")])
      assert.are.equals(16, #_G.free_dip_internal_ips[ip2int("192.168.220.203")])
      assert.are.equals(16, #_G.free_dip_internal_ips[ip2int("192.168.220.204")])
   end)
end)
