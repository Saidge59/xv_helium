local json = require('cjson')

function is_nil_or_empty(s)
    return s == nil or
        (type(s) == string and s == '') or
        (type(s) == table and #s == 0)
end

---Return true if the table contains the item
function table.contains(table, item)
    for _, value in ipairs(table) do
        if value == item then
            return true
        end
    end
    return false
end

---Return true if any of the table items starts with the given prefix
function table.contains_prefix(table, prefix)
    for _, value in ipairs(table) do
        if string.sub(value, 1, #prefix) == prefix then
            return true
        end
    end
    return false
end

---Returns the first element of the table which starts with the given prefix
function table.find_prefix(table, prefix)
    for _, value in ipairs(table) do
        if string.sub(value, 1, #prefix) == prefix then
            return value
        end
    end
    return nil
end

---Load table from a JSON file
---@param path string: Path to the auth token config file
---@return table|nil config A lua table contains all the configs. Return nil if there's any error opening the file.
---@note This function panic if the config file is not a valid json.
function load_table_from_json_file(path)
    local f = io.open(path, "rb")
    if not f then
        return nil
    end
    local d = f:read "*a"
    f:close()
    return json.decode(d)
end

function parse_ipv4(ip)
    if not ip or type(ip) ~= "string" then return nil end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if a == nil or b == nil or c == nil or d == nil then
        return nil
    end

    a = tonumber(a)
    b = tonumber(b)
    c = tonumber(c)
    d = tonumber(d)
    if a < 0 or a > 255 then return nil end
    if b < 0 or b > 255 then return nil end
    if c < 0 or c > 255 then return nil end
    if d < 0 or d > 255 then return nil end

    return a, b, c, d
end

---Convert an unsigned integer netlong from network byte order to host byte order
function ntohl(netlong)
    local a = netlong & 0xFF
    local b = (netlong >> 8) & 0xFF
    local c = (netlong >> 16) & 0xFF
    local d = (netlong >> 24) & 0xFF
    return (a << 24) + (b << 16) + (c << 8) + d
end

---Convert an unsigned integer hostlong from host byte order to network byte order
function htonl(hostlong)
    local a = hostlong & 0xFF
    local b = (hostlong >> 8) & 0xFF
    local c = (hostlong >> 16) & 0xFF
    local d = (hostlong >> 24) & 0xFF
    return (a << 24) + (b << 16) + (c << 8) + d
end

---Convert an ipv4 address to integer value in network byte order
---@param ip string: IP address
---@return integer result Return the integer value of the ip address. Return -1 if the address is not valid.
function ip2int(ip)
    local a, b, c, d = parse_ipv4(ip)
    if a == nil or b == nil or c == nil or d == nil then
        return -1
    end
    if a < 0 or a > 255 then return -1 end
    if b < 0 or b > 255 then return -1 end
    if c < 0 or c > 255 then return -1 end
    if d < 0 or d > 255 then return -1 end

    -- Network Byte Order
    return (d << 24) + (c << 16) + (b << 8) + a
end

---Convert an integer to ip address
---@param ip_int integer: The integer value of an ipv4 address
---@return string ip Return the string format of the ip address.
function int2ip(ip_int)
    if ip_int < 0 or ip_int > 0xFFFFFFFF then
        return nil
    end
    local d = (ip_int >> 24) & 0xFF
    local c = (ip_int >> 16) & 0xFF
    local b = (ip_int >> 8) & 0xFF
    local a = ip_int & 0xFF

    return string.format("%d.%d.%d.%d", a, b, c, d)
end

function parse_ipv4_cidr(ip)
    if not ip or type(ip) ~= "string" then return nil end
    local ip, mask = ip:match("^(%d+%.%d+%.%d+%.%d+)/(%d+)$")
    if ip == nil or mask == nil then
        return nil
    end

    mask = tonumber(mask)
    if mask < 0 or mask > 32 then return nil end

    ip = ip2int(ip)
    if ip < 0 then return nil end

    return ip, mask
end

---Checks if the given string is a valid ipv4 address
---@param ip string|integer: A string or integer containing an IPv4 address
---@return boolean result Return true if the input is a valid ipv4 address
function is_ipv4(ip)
    if ip == nil then return false end
    if type(ip) == "string" then
        local a, b, c, d = parse_ipv4(ip)
        if a == nil or b == nil or c == nil or d == nil then
            return false
        else
            return true
        end
    elseif type(ip) == "number" then
        return ip >= 0 and ip <= 0xFFFFFFFF
    else
        return false
    end
end

---Parse the internal_ip config into ip and cidr
---@param internal_ip string: The internal_ip string that the server expects from the server config
---@return (integer ip, integer mask) when the input is valid
function parse_internal_ip_cidr(internal_ip)
    local internal_ip_cidr = get_internal_ip_cidr_str(internal_ip)
    if internal_ip_cidr == nil then
        return nil
    end

    local ip_u32, mask = parse_ipv4_cidr(internal_ip_cidr)
    if ip_u32 == nil then
        return nil
    end
    
    return ip_u32, mask
end

---Calculate local_ip with internal_ip
---@param internal_ip string: The internal_ip string that the server expects from the server config
---@return string local_ip
function get_local_ip_str(internal_ip)
    local ip_u32, mask = parse_internal_ip_cidr(internal_ip)
    if ip_u32 == nil then
        return nil
    end
    
    local local_ip_int = ntohl(ip_u32) + 1
    return int2ip(ntohl(local_ip_int))
end

---Calculate peer_ip with internal_ip
---@param internal_ip string: The internal_ip string that the server expects from the server config
---@return string peer_ip
function get_peer_ip_str(internal_ip)
    local ip_u32, mask = parse_internal_ip_cidr(internal_ip)
    if ip_u32 == nil then
        return nil
    end
    
    local peer_ip_int = ntohl(ip_u32) + 2
    return int2ip(ntohl(peer_ip_int))
end

---Retrieve CIDR format of the internal_ip, accepts the CIDR format (new) and the prefix format (old)
---@param internal_ip string: The internal_ip string that the server expects from the server config
---@return string internal_ip_cidr
function get_internal_ip_cidr_str(internal_ip)
    if internal_ip:match("^(%d+%.%d+%.%d+%.%d+)/(%d+)$") then
        return internal_ip
    end

    -- Assume /16 range if the internal_ip is in the old format
    if internal_ip:match("^(%d+)%.(%d+)$") then
        return internal_ip .. ".0.0/16"
    end

    return nil
end

---Create an IP pool for a given cidr range
---@param cidr string: The cidr
---@param full_range bool: If true use the full range, otherwise omit the network and broadcast address (first and last)
---@return table the pool
function make_ip_pool(cidr, full_range)
    -- Calculate the start and end ip from the ip pool cidr
    local ip_u32, mask = parse_internal_ip_cidr(cidr)
    if ip_u32 == nil then
        return nil, string.format("invalid cidr: %s", cidr)
    end

    if mask < 16 then return nil, "ip range too large" end
    if mask > 29 then return nil, "ip range too small" end

    local peer_ip_int = ip2int(peer_ip)
    local dns_ip_int = ip2int(dns_ip)
    local client_ip_int = ip2int(client_ip)

    local start_ip = ntohl(ip_u32)
    local end_ip = start_ip + (1 << (32 - mask)) - 1
    -- Excluding the broadcast and network addresses of the range
    if not full_range then
       start_ip = start_ip + 1
       end_ip = end_ip - 1
    end


    -- Fill the ip pool
    local pool = {}
    for ip = start_ip, end_ip do
        if ip ~= ntohl(peer_ip_int) and ip ~= ntohl(dns_ip_int) and ip ~= ntohl(client_ip_int) then
            table.insert(pool, htonl(ip))
        end
    end

    function pool:allocate()
      -- Check the number of IPs available before returning
       if #self == 0 then
           return nil
       else
           return table.remove(self)
       end
    end

    function pool:release(ip)
       -- Insert released IP address into the start of the list to emulate a first in last out queue
       table.insert(self, 1, ip)
    end

    return pool, nil
end
