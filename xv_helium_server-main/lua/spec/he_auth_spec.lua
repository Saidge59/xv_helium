-- Set global variables which are required by the he_auth functions
_G.auth_path = "../test/support/test_db.sqlite3"
_G.internal_ip = "10.125"
_G.peer_ip = "185.198.242.5"
_G.client_ip = "185.198.242.6"
_G.dns_ip = "185.198.242.1"

-- Import the script for testing
require("he_auth")

describe('auth_user', function()
    it('should return false when using empty username/password', function()
        assert.is_false(auth_user("", ""))
        assert.is_false(auth_user("", "test"))
        assert.is_false(auth_user("test", ""))
    end)

    it('should return false when using invalid password', function()
        assert.is_false(auth_user("test", "invalid"))
    end)

    it("should return false when user doesn't exist", function()
        assert.is_false(auth_user("test1", "test"))
    end)

    it("should return true with valid user/pass", function()
        assert.is_true(auth_user("test", "test"))
    end)

    it("benchmark", function()
        -- verify the user/pass 1000 times
        local n = 1000
        local elapsed = 0
        local start = os.clock()
        for i = 1, n do
            assert.is_true(auth_user("test", "test"))
        end
        elapsed = os.clock() - start
        print(string.format('Benchmark auth_user: verified %d times in %.3f seconds, %.1f ms/op', n, elapsed,
            elapsed * 1000 / n))
    end)
end)

describe('global_ip_pool', function()
    it("should assign from global pool", function()
        _G.free_ips, err = make_ip_pool("10.125.0.0/24", false)

        assert.is_nil(err)
        assert.equals(254, #_G.free_ips)

        local local_ip = allocate_ip()
        assert.equals(ip2int("10.125.0.254"), local_ip)
        assert.equals(253, #_G.free_ips)

        release_ip(local_ip)
        assert.equals(254, #_G.free_ips)
    end)

end)
