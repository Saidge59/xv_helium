require "he_auth_token"

local jwt = require "lua-jwt/src/jwt"

-- This is the Auth0 public key we get via this command:
-- curl -s https://auth.expressvpn.com/pem | openssl x509 -pubkey -noout
local auth0_public_key = [[-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqYR1c4q9SVL4s2BCbfgi
Y0Rk1W9C/oEwp4NX+1i/Sv+NPhZfPNHcj6eQNgaIPqSVuXRhFMR3CxRTqUApX2yY
mVfUbYQp/ExL2sG2O8G5fmTMXEB8dqzuKFPyp/jbcHE/egwe15Bomb8nSvkDdYXI
W18kmT2GUvbeCvY81+0ZwKjIHNsRZs9jnFudfgCx6mUWi3lBtPM9WjOlm7SN5jQl
/BgoNMS1Spw91uKBZRokQ9LxIzPahpfh2a7WQeWZrVd/3EdGVmkpdaMhiTaBpLEp
/0l1LP38B5SpeCDdIsFydKEcHvEm/rRcBpFgat0Fak2faB7RtWHVUG/vH3TPSz8e
QwIDAQAB
-----END PUBLIC KEY-----]]

-- openssl genrsa -out key.pem 2048
local good_private_key = [[-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCuoe2BSS4sWRxc
nlVKI+eZbgTVtRiMI1xSOdHlb9RT5oMQEjxd9xGhSU1IsyZmPsj1Bcpjjkduxaeh
T2kunsNHZd6qgU3KRPOMJvIlGdeskWPMAXBOJJhi8KL292vBvg/R2ntf3Dce8xIt
gLrn2UZFBFf09yRCgyckN1BwmmHQX45DgmntCqQF68DDmG9ELonLUVukqm6DSXt2
S2oOK+sOF98djDHv6ZyefA/7lbF9hcCt9ZOAshcQ9wm0XGv/HPOPLX1kt0EMBOFA
XVx9aqqHZpCN065CnW80oWTKCeZ4juZzfciAw4e7Ij1MhZkF6mPMRlQJqP92tzCg
cz8B64XdAgMBAAECggEADR+xMXv2QtydiN5YoDOWO6MXgkH+VXBw3I2+LEUdCq3H
oA+8G/8DLauhvxAWQi0qErPmiQMlHiTaMKwURlh7FM9fOPwdBFGYkKn6nPbWDQDO
JFjf/5djdl1e5JAlN9BYmwJALwI7MucR23vm+qE1qoklh7eCW5dEpprw6iLIAriT
3En9hZtFuao8vUBstOMhw5OUsgnYx6u9sO4yJzNerqo7PIZGEWu36E7s4U7Ly1PV
pYQsuoE0A06CYmwcwG3BFyv1C5G6kx2SwCveZHiAlMp33e3gY67vffg+pMNZJK3/
76XTXRkDK2vCwG6b1olR82jX0gOfcOTM5e8MQagfUQKBgQDKq+OpTVNog8nIoYiB
FcEnzwGnD5mySity7UuwdbJA/bwv6gbMcu+Z8OJFIT4yN1TqQ9pNVh5yBkBlRyTT
LC0vVm2MB1DBOgUkwwRvjcW+xx43ZbrvvyrOWKInF6PM2jdEVc/A5Pzt6JhwTdWS
prwJB83dG8ht4cb4l5unIgjJVQKBgQDclVCa0n3XGU/99r0fgDkTkOgxzLJnnFwD
+ml4QYyz9sE8sHDcP2cLCVm6fCyyWnkJSFstSRmZflrC6BWjPlBkeTeekj9pvxax
BkJ8LaaU3QhSEST364RGP9oHDxoWUzxE/5sKM+VJ4kGuWj7NizCDJqrn5upGB++H
Kt1ReiUqaQKBgFhe2sXXkabgz/tLc9nVQoO5H19YzguPi6JxFa+7oh30hTnfMVe0
RgU5o2/BLv12YvBC5c0S3/OYBjwi6Uuq14jshpeoGO4n/lYpMqXxi2fEKsi88uXW
1TNkMlAZXrLT84U4ZX4WWrLh2JYfWiC30wWdAYaHtr0y1S9P6+7USECBAoGBALYb
59IKGa5tzWakP/szxutqZOhIULnNkwINyOlpZJpnC53pJSQQjCfGbnfRcK1GmEqb
m/rFMQdSE+h55vNAzOpGUS7vGr9Y7Yj03ArdPXwFB4uJb/XmUOwWZxAQ3b60tTtZ
s0w3EANxcjxZcSQM195PHCYctClg/9WeA93yc6CRAoGBAKIxlaSE/iUV/FyNR73C
6IPe3EY3tGNE4sRPej2gMDH0PAE7XnkJsI8ZyQ+32yhL7w6RDd+aww/fmqC4o5qo
+UqniUnNqr1cb0R7NRyl4dFtX2JaXWX+k8dWWvLAbdNNIk6OJfojZedQ4TG6u4p+
ihgbfuapwWj2Ohg3iG+rlJ9t
-----END PRIVATE KEY-----]]

-- openssl rsa -in key.pem -pubout > key.pub
local good_public_key = [[-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArqHtgUkuLFkcXJ5VSiPn
mW4E1bUYjCNcUjnR5W/UU+aDEBI8XfcRoUlNSLMmZj7I9QXKY45HbsWnoU9pLp7D
R2XeqoFNykTzjCbyJRnXrJFjzAFwTiSYYvCi9vdrwb4P0dp7X9w3HvMSLYC659lG
RQRX9PckQoMnJDdQcJph0F+OQ4Jp7QqkBevAw5hvRC6Jy1FbpKpug0l7dktqDivr
DhffHYwx7+mcnnwP+5WxfYXArfWTgLIXEPcJtFxr/xzzjy19ZLdBDAThQF1cfWqq
h2aQjdOuQp1vNKFkygnmeI7mc33IgMOHuyI9TIWZBepjzEZUCaj/drcwoHM/AeuF
3QIDAQAB
-----END PUBLIC KEY-----]]

describe('auth_user_with_token_and_key', function()
    it('should return false if token or key is empty/nil', function()
        assert.is_false(auth_user_with_token_and_key(nil, 'a public key'))
        assert.is_false(auth_user_with_token_and_key('', 'a public key'))
        assert.is_false(auth_user_with_token_and_key('access token', nil))
        assert.is_false(auth_user_with_token_and_key('access token', ''))
    end)

    it('should return true for a good token', function()
        local claims = {
            kp_user = "krn::iam::xvpn:user:16d3ca79-20b3-40eb-9793-ea5717ae54d3",
            iat = 1693473874,
            nbf = 1693473875,
            exp = 2000000000, -- Wed May 18 11:33:20 2033
            scope = "openid profile email"
        }

        -- Generate and sign the token with the local generated private key
        local token = jwt.encode(claims, {
            alg = "RS256",
            keys = {
                private = good_private_key
            }
        })
        print("token: " .. token)

        -- Verify the token with the public key
        local result, err = auth_user_with_token_and_key(token, good_public_key)
        assert.is_true(result)
        assert.is_nil(err)
    end)

    it('should return false when using an invalid key', function()
        local claims = {
            kp_user = "krn::iam::xvpn:user:16d3ca79-20b3-40eb-9793-ea5717ae54d3",
            iat = 1693473874,
            nbf = 1693473875,
            exp = 2000000000, -- Wed May 18 11:33:20 2033
            scope = "openid profile email"
        }

        -- Generate and sign the token with the local generated private key
        local token = jwt.encode(claims, {
            alg = "RS256",
            iss = "https://localhost/",
            sub = "local",
            keys = {
                private = good_private_key
            }
        })

        -- Try verify the token with a wrong public key
        local result, err = auth_user_with_token_and_key(token, auth0_public_key)
        assert.are.equals("Invalid token: signature verify failed", err)
        assert.is_false(result)
    end)

    it('should return false for a non RS256 token', function()
        local claims = {
            kp_user = "krn::iam::xvpn:user:16d3ca79-20b3-40eb-9793-ea5717ae54d3",
            iat = 1693473874,
            nbf = 1693473875,
            exp = 2000000000, -- Wed May 18 11:33:20 2033
            scope = "openid profile email"
        }

        -- Generate and sign the token with the local generated private key
        local token = jwt.encode(claims, {
            alg = "HS256",
            keys = {
                private = good_private_key
            }
        })

        -- Verify the token with the public key
        local result, err = auth_user_with_token_and_key(token, good_public_key)
        assert.is_false(result)
        assert.is_not_nil(err)
        assert.are.equals("Jwt uses a disallowed algorithm", err)

        local plain_token = jwt.encode(claims)
        result, err = auth_user_with_token_and_key(plain_token, good_public_key)
        assert.is_false(result)
        assert.is_not_nil(err)
        assert.are.equals("Jwt uses a disallowed algorithm", err)
    end)

    it('benchmark test', function()
        local claims = {
            kp_user = "krn::iam::xvpn:user:16d3ca79-20b3-40eb-9793-ea5717ae54d3",
            iat = 1693473874,
            nbf = 1693473875,
            exp = 2000000000, -- Wed May 18 11:33:20 2033
            scope = "openid profile email",
            iss = "https://localhost/",
            sub = "local"
        }
        local keys = {
            private = good_private_key,
            public = good_public_key
        }

        -- Generate and sign the token with the local generated private key
        local token = jwt.encode(claims, {
            alg = "RS256",
            keys = {
                private = keys.private
            }
        })

        -- Verify the token with the public key mutliple times
        local n = 1000
        local elapsed = 0
        local start = os.clock()
        for i = 1, n do
            assert.is_true(auth_user_with_token_and_key(token, keys.public))
        end
        elapsed = os.clock() - start
        print(string.format('Benchmark auth_user_with_token: decoded %d tokens in %.3f seconds, %.1f ms/token', n,
            elapsed, elapsed * 1000 / n))
    end)

    describe('with leeway', function()
        local claims = {
            iat = os.time(),       -- issued at now
            nbf = os.time() - 300, -- not before: 300 seconds ago
            exp = os.time() - 5,   -- expired 5 seconds ago
            aud = "VPNCONNECTION",
            scope = "openid profile email"
        }
        -- Generate and sign the token
        local token = jwt.encode(claims, {
            alg = "RS256",
            keys = {
                private = good_private_key
            }
        })
        it('should return false if the diff is larger than the leeway', function()
            local result, err = auth_user_with_token_and_key(token, good_public_key, 1)
            assert.is_false(result)
            assert.are.equals("expired", err)
        end)
        it('should return true if the diff is within the leeway', function()
            local result, err = auth_user_with_token_and_key(token, good_public_key, 10)
            assert.is_true(result)
            assert.is_nil(err)
        end)
    end)
end)

describe('auth_user_with_token', function()
    it('should return false if token is empty/nil', function()
        assert.is_false(auth_user_with_token(nil))
        assert.is_false(auth_user_with_token(''))
    end)

    describe('with multiple keys', function()
        -- Load all keys from test config
        local err = load_all_auth_token_keys("support/auth_token.json")
        assert.is_nil(err)

        -- Connection Authorization Token (CAT)
        -- https://polymoon.atlassian.net/wiki/spaces/KPL/pages/3084749334/JSON+Web+Token+JWT#Connection-Authorization-Token-(CAT)
        it('should return true for valid normal vpn token', function()
            local claims = {
                iat = os.time(),
                nbf = os.time() - 10,
                exp = 2000000000, -- Wed May 18 11:33:20 2033
                aud = "xv.vpn",
                iss = "xv.cats",
                entitlements = {}
            }
            claims.entitlements["xv.vpn"] = {}
            local token = jwt.encode(claims, {
                alg = "RS256",
                kid = "xv-debug-pubkey",
                keys = {
                    private = good_private_key
                }
            })
            print("vpn token: " .. token)

            local result, err = auth_user_with_token(token)
            assert.is_nil(err)
            assert.is_true(result)
        end)
    end)
end)

-- Dedicated IP Authorization Token (DAT)
-- https://polymoon.atlassian.net/wiki/spaces/KPL/pages/3084749334/JSON+Web+Token+JWT#Dedicated-IP-Authorization-Token-(DAT)
describe('auth_user_with_dip_token', function()
    it('should load dip config without error', function()
        -- Load all keys from test config
        local err = load_all_auth_token_keys("support/auth_token_dip.json")
        assert.is_nil(err)
    end)

    it('should return true for valid dip vpn token', function()
        local dip = os.getenv("TESTING_DIP") or "1.2.3.4"
        local claims = {
            iat = os.time(),
            nbf = os.time() - 10,
            exp = 2000000000, -- Wed May 18 11:33:20 2033
            aud = "xv.vpn.dip",
            iss = "xv.dcts",
            entitlements = {}
        }
        claims.entitlements["xv.vpn.dip.details"] = { ip = dip };
        local token = jwt.encode(claims, {
            alg = "RS256",
            kid = "xv-dip-local-testing",
            keys = {
                private = good_private_key
            }
        })
        print("dip token: " .. token)
        local result, err = auth_user_with_dip_token(token, dip)
        assert.is_nil(err)
        assert.is_true(result)
    end)

    it('should return false if the token dip is different than the expected dip', function()
        local claims = {
            iat = os.time(),
            nbf = os.time() - 10,
            exp = 2000000000, -- Wed May 18 11:33:20 2033
            aud = "xv.vpn.dip",
            iss = "xv.dcts",
            entitlements = {}
        }
        claims.entitlements["xv.vpn.dip.details"] = { ip = "1.2.3.4" }
        local token = jwt.encode(claims, {
            alg = "RS256",
            kid = "xv-dip-local-testing",
            keys = {
                private = good_private_key
            }
        })
        local result, err = auth_user_with_dip_token(token, "4.3.2.1")
        assert.are.equals("invalid dip", err)
        assert.is_false(result)
    end)

    it("should return error if kid doesn't match", function()
        local claims = {
            iat = os.time(),
            nbf = os.time() - 10,
            exp = os.time() + 10,
            scope = "openid profile email",
            aud = "xv.vpn.dip"
        }
        local token = jwt.encode(claims, {
            alg = "RS256",
            kid = "xv-staging-pubkey",
            keys = {
                private = good_private_key
            }
        })
        local result, err = auth_user_with_dip_token(token, "1.2.3.4")
        assert.are.equals("public key not set", err)
        assert.is_false(result)
    end)

    it("should return error if aud doesn't match", function()
        local claims = {
            iat = os.time(),
            nbf = os.time() - 10,
            exp = 2000000000, -- Wed May 18 11:33:20 2033
            aud = "cg.vpn.dip",
            entitlements = {}
        }
        claims.entitlements["xv.vpn.dip.details"] = { ip = "1.2.3.4" }
        local token = jwt.encode(claims, {
            alg = "RS256",
            kid = "xv-dip-local-testing",
            keys = {
                private = good_private_key
            }
        })
        print("dip token: " .. token)
        local result, err = auth_user_with_dip_token(token, "1.2.3.4")
        assert.are.equals("invalid audience", err)
        assert.is_false(result)
    end)

    it("should return error if entitlements doesn't match", function()
        local claims = {
            iat = os.time(),
            nbf = os.time() - 10,
            exp = 2000000000, -- Wed May 18 11:33:20 2033
            aud = "xv.vpn.dip",
            entitlements = {}
        }
        claims.entitlements["cg.vpn.dip.details"] = { ip = "1.2.3.4" }
        local token = jwt.encode(claims, {
            alg = "RS256",
            kid = "xv-dip-local-testing",
            keys = {
                private = good_private_key
            }
        })
        local result, err = auth_user_with_dip_token(token, "1.2.3.4")
        assert.are.equals("invalid entitlements", err)
        assert.is_false(result)
    end)
end)
