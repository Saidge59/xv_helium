require('he_utils')

local json = require('cjson')

function init_dip_internal_ip_map()
   local f, err = io.open(dip_internal_ip_map, "rb")
   if not f then
      error("Failed to open " .. dip_internal_ip_map .. ": " .. err)
   end
   local d = f:read "*a"
   f:close()
   local m = json.decode(d)

   local pools = {}

   for dip, range in pairs(m) do
      pools[ip2int(dip)] = make_ip_pool(range, true)
   end

   return pools
end

---Allocate an internal IP for the given dip
function allocate_dip_ip(dip)
   local p = free_dip_internal_ips[dip]
   if not p then
      return nil
   end

   return p:allocate()
end

---Release the given internal IP for the given dip
---No attempt is made to ensure that ip is within dip's range
function release_dip_ip(dip, ip)
   local p = free_dip_internal_ips[dip]
   if not p then
      return nil
   end
   return p:release(ip)
end

free_dip_internal_ips = init_dip_internal_ip_map()
