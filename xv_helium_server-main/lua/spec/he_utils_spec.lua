require "he_utils"

local inspect = require "inspect"

describe("load_table_from_json_file", function()
    it("should return nil if the config file doesn't exist", function()
        local cfg = load_table_from_json_file("/tmp/not_exist.json")
        assert.is_nil(cfg)
    end)

    it("should panic when parsing an invalid json file", function()
        assert.has.error(function()
            local cfg = load_table_from_json_file("support/auth_token_invalid.json")
            assert.is_nil(cfg)
        end)
    end)

    it("should return cfg if the config file is loaded successfully", function()
        local cfg = load_table_from_json_file("support/auth_token.json")
        assert.is_not_nil(cfg)
        print(inspect(cfg))
        assert.equals(1, cfg.version)
        assert.are.same({ "xv.vpn" }, cfg.audiences)
        local key1 = cfg.auth_token_public_keys["xv-prod-public-key"]
        assert.equals("/path/to/public_key1.pem", key1.path)
        local key2 = cfg.auth_token_public_keys["xv-debug-pubkey"]
    end)
end)

describe("is_ipv4", function()
    it("should return true for valid ip addresses string", function()
        assert.is_true(is_ipv4("0.0.0.0"))
        assert.is_true(is_ipv4("255.255.255.255"))
        assert.is_true(is_ipv4("1.2.3.4"))
        assert.is_true(is_ipv4("255.0.0.0"))
    end)

    it("should return true for valid ip addresses number", function()
        assert.is_true(is_ipv4(0))          -- 0.0.0.0
        assert.is_true(is_ipv4(0xFFFFFFFF)) -- 255.255.255.255
        assert.is_true(is_ipv4(1234))
        assert.is_true(is_ipv4(0x7F000001)) -- 127.0.0.1
    end)

    it("should return false for invalid ip addresses", function()
        assert.is_false(is_ipv4(nil))
        assert.is_false(is_ipv4(""))
        assert.is_false(is_ipv4("  1.2.3.4"))
        assert.is_false(is_ipv4("1.2.3.4    "))
        assert.is_false(is_ipv4("something"))
        assert.is_false(is_ipv4("1.0/32"))
        assert.is_false(is_ipv4("1.2.3"))
        assert.is_false(is_ipv4("256.256.256.999"))
        assert.is_false(is_ipv4("1.2.3.4.5"))
    end)

    it("should return false for invalid ip addresses number", function()
        assert.is_false(is_ipv4(-1))
        assert.is_false(is_ipv4(0x100000000))
    end)

    it("should return false for invalid ip addresses type", function()
        assert.is_false(is_ipv4({}))
    end)
end)

describe("int2ip", function()
    it("should convert int to ip address correctly", function()
        assert.equals("0.0.0.0", int2ip(0))
        assert.equals("127.0.0.1", int2ip(0x0100007F))
        assert.equals("192.168.1.1", int2ip(0x0101A8C0))
        assert.equals("255.255.255.255", int2ip(0xFFFFFFFF))
    end)

    it("should return nil for invalid input", function()
        assert.is_nil(int2ip(-1))
        assert.is_nil(int2ip(4294967296))
    end)
end)

describe("ip2int", function()
    it("should convert ip address to int correctly", function()
        assert.equals(0, ip2int("0.0.0.0"))
        assert.equals(0x0100007F, ip2int("127.0.0.1"))
        assert.equals(0x0101A8C0, ip2int("192.168.1.1"))
        assert.equals(0xFFFFFFFF, ip2int("255.255.255.255"))
    end)

    it("should return -1 for invalid input", function()
        assert.equals(-1, ip2int(-1))
        assert.equals(-1, ip2int(nil))
        assert.equals(-1, ip2int(""))
        assert.equals(-1, ip2int({}))
        assert.equals(-1, ip2int("999.0.0.1"))
    end)
end)

describe("get_local_ip_str", function()
    it("should convert the global variable internal_ip to correct local ip", function()
        assert.equals("192.168.1.1", get_local_ip_str("192.168.1.0/24"))
        assert.equals("10.125.0.1", get_local_ip_str("10.125.0.0/24"))
        assert.equals("10.125.0.1", get_local_ip_str("10.125"))
    end)

    it("should return nil when error", function()
        assert.equals(nil, get_local_ip_str(""))
        assert.equals(nil, get_local_ip_str("10"))
        assert.equals(nil, get_local_ip_str("10.125.0"))
        assert.equals(nil, get_local_ip_str("10.125.0.0"))
    end)
end)

describe("get_peer_ip_str", function()
    it("should convert the global variable internal_ip to correct peer ip", function()
        assert.equals("192.168.1.2", get_peer_ip_str("192.168.1.0/24"))
        assert.equals("10.125.0.2", get_peer_ip_str("10.125"))
    end)

    it("should return nil when error", function()
        assert.equals(nil, get_peer_ip_str(""))
        assert.equals(nil, get_peer_ip_str("10"))
        assert.equals(nil, get_peer_ip_str("10.125.0"))
        assert.equals(nil, get_peer_ip_str("10.125.0.0"))
    end)
end)

describe("get_internal_ip_cidr_str", function()
    it("should return the internal_ip_cidr based on internal_ip", function()
        assert.equals("192.168.1.0/24", get_internal_ip_cidr_str("192.168.1.0/24"))
        assert.equals("192.168.0.0/16", get_internal_ip_cidr_str("192.168"))
    end)

    it("should return nil when error", function()
        assert.equals(nil, get_internal_ip_cidr_str(""))
        assert.equals(nil, get_internal_ip_cidr_str("10"))
        assert.equals(nil, get_internal_ip_cidr_str("10.125.0"))
        assert.equals(nil, get_internal_ip_cidr_str("10.125.0.0"))
    end)
end)

describe('make_ip_pool', function()
    it("should fill the pool with free ips", function()
        local pool, err = make_ip_pool("10.125.0.0/24", false)

        assert.is_nil(err)
        assert.equals(254, #pool)

        local local_ip = pool:allocate()
        assert.equals(ip2int("10.125.0.254"), local_ip)
        assert.equals(253, #pool)

        pool:release(local_ip)
        assert.equals(254, #pool)
    end)

    it("should fill the pool with full range of free ips", function()
        local pool, err = make_ip_pool("10.125.0.0/24", true)

        assert.is_nil(err)
        assert.equals(256, #pool)

        local local_ip = pool:allocate()
        assert.equals(ip2int("10.125.0.255"), local_ip)
        assert.equals(255, #pool)

        pool:release(local_ip)
        assert.equals(256, #pool)
    end)

    it("should assume the internal_ip is /16 range for old format", function()
        local pool, err = make_ip_pool("10.125", false)

        assert.is_nil(err)
        assert.equals(65534, #pool)

        local local_ip = pool:allocate()
        assert.equals(ip2int("10.125.255.254"), local_ip)
        assert.equals(65533, #pool)

        pool:release(local_ip)
        assert.equals(65534, #pool)
    end)

    it("should return err if the internal_ip is malformed", function()
        local pool, err = make_ip_pool("10.125/24", false)

        assert.is_nil(pool)
        assert.is_not_nil(err)
    end)
end)
