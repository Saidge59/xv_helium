describe("JWT spec", function()

  local jwt  = require 'jwt'
  local crypto = pcall (require, 'crypto') and require 'crypto'
  local pkey = require 'jwt.utils'.pkey
  local plainJwt = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

  it("can decode a plain text token", function()
    local token, msg = jwt.decode(plainJwt)
    assert(token or error(msg))
    assert(token.iss == "joe")
    assert(token.exp == 1300819380)
    assert(token["http://example.com/is_root"] == true)
  end)

  it("can encode a plain text token", function()
    local claim = {
      iss = "joe",
      exp = 1300819380,
      ["http://example.com/is_root"] = true
    }
    local token = jwt.encode(claim)
    assert.are.same(jwt.decode(token), claim)
    assert.are.same(jwt.decode(plainJwt), claim)
  end)

  it("it can encode/decode a signed plain text token with alg=HS256", function()
    local claims = {
      test = "test",
    }
    local token = jwt.encode(claims, {alg = "HS256", keys = {private = "key"}})
    local decodedClaims = jwt.decode(token, {keys = {public = "key"}})
    assert.are.same(claims, decodedClaims)
  end)

  it("it cannot encode/decode a signed plain text token with alg=HS256 and an incorrect key", function()
    local claims = {
      test = "test",
    }
    local token = jwt.encode(claims, {alg = "HS256", keys = {private = "key"}})
    local decodedClaims = jwt.decode(token, {keys = {public = "notthekey"}})
    assert.has_error(function() assert.are.same(claims, decodedClaims) end)
  end)

  it("it can encode/decode a signed plain text token with alg=RS256", function()
    local claims = {
      test = "test",
      empty={},
    }
    local keys = {
      private =
[[-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANfnFz7xPmYVdJxZE7sQ5quh/XUzB5y/D5z2A7KPYXUgUP0jd5yL
Z7+pVBcFSUm5AZXJLXH4jPVOXztcmiu4ta0CAwEAAQJBAJYXWNmw7Cgbkk1+v3C0
dyeqHYF0UD5vtHLxs/BWLPI2lZO0e6ixFNI4uIuatBox1Zbzt1TSy8T09Slt4tNL
CAECIQD6PHDGtKXcI2wUSvh4y8y7XfvwlwRPU2AzWZ1zvOCbbQIhANzgMpUNOZL2
vakju4sal1yZeXUWO8FurmsAyotAx9tBAiB2oQKh4PAkXZKWSDhlI9CqHtMaaq17
Yb5geaKARNGCPQIgILYrh5ufzT4xtJ0QJ3fWtuYb8NVMIEeuGTbSyHDdqIECIQDZ
3LNCyR2ykwetc6KqbQh3W4VkuatAQgMv5pNdFLrfmg==
-----END RSA PRIVATE KEY-----]],
      public =
[[-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANfnFz7xPmYVdJxZE7sQ5quh/XUzB5y/
D5z2A7KPYXUgUP0jd5yLZ7+pVBcFSUm5AZXJLXH4jPVOXztcmiu4ta0CAwEAAQ==
-----END PUBLIC KEY-----]],
    }
    local token, _ = jwt.encode(claims, {alg = "RS256", keys = { private = keys.private }})
    local decodedClaims, err = jwt.decode(token, {keys = { public = keys.public }})
    assert.table(decodedClaims, err)
    assert.are.same(claims, decodedClaims)
  end)

  if crypto then
    it("it cannot encode/decode a signed plain text token with alg=RS256 (using luacrypto pkey)", function()
      local claims = {
        test = "test",
        empty={},
      }
      local key = crypto.pkey.generate("rsa", 512)
      local private_key =
[[-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANfnFz7xPmYVdJxZE7sQ5quh/XUzB5y/D5z2A7KPYXUgUP0jd5yL
Z7+pVBcFSUm5AZXJLXH4jPVOXztcmiu4ta0CAwEAAQJBAJYXWNmw7Cgbkk1+v3C0
dyeqHYF0UD5vtHLxs/BWLPI2lZO0e6ixFNI4uIuatBox1Zbzt1TSy8T09Slt4tNL
CAECIQD6PHDGtKXcI2wUSvh4y8y7XfvwlwRPU2AzWZ1zvOCbbQIhANzgMpUNOZL2
vakju4sal1yZeXUWO8FurmsAyotAx9tBAiB2oQKh4PAkXZKWSDhlI9CqHtMaaq17
Yb5geaKARNGCPQIgILYrh5ufzT4xtJ0QJ3fWtuYb8NVMIEeuGTbSyHDdqIECIQDZ
3LNCyR2ykwetc6KqbQh3W4VkuatAQgMv5pNdFLrfmg==
-----END RSA PRIVATE KEY-----]]
      local token, _ = jwt.encode(claims, {alg = "RS256", keys = { private = private_key }})
      assert.has.error (function ()
        jwt.encode(claims, {alg = "RS256", keys = {private = key}})
      end)
      assert.has.error (function ()
        jwt.decode(token, {keys = {public = key}})
      end)
    end)
  end

  it("it cannot encode/decode a signed plain text token with alg=RS256 (using luaossl pkey)", function()
    local claims = {
      test = "test",
      empty={},
    }
    local key = pkey.new{type = "rsa", bits=512}
    local private_key =
[[-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANfnFz7xPmYVdJxZE7sQ5quh/XUzB5y/D5z2A7KPYXUgUP0jd5yL
Z7+pVBcFSUm5AZXJLXH4jPVOXztcmiu4ta0CAwEAAQJBAJYXWNmw7Cgbkk1+v3C0
dyeqHYF0UD5vtHLxs/BWLPI2lZO0e6ixFNI4uIuatBox1Zbzt1TSy8T09Slt4tNL
CAECIQD6PHDGtKXcI2wUSvh4y8y7XfvwlwRPU2AzWZ1zvOCbbQIhANzgMpUNOZL2
vakju4sal1yZeXUWO8FurmsAyotAx9tBAiB2oQKh4PAkXZKWSDhlI9CqHtMaaq17
Yb5geaKARNGCPQIgILYrh5ufzT4xtJ0QJ3fWtuYb8NVMIEeuGTbSyHDdqIECIQDZ
3LNCyR2ykwetc6KqbQh3W4VkuatAQgMv5pNdFLrfmg==
-----END RSA PRIVATE KEY-----]]
    local token, _ = jwt.encode(claims, {alg = "RS256", keys = { private = private_key }})
    assert.has.error (function ()
      jwt.encode(claims, {alg = "RS256", keys = {private = key}})
    end)
    assert.has.error (function ()
      jwt.decode(token, {keys = {public = key}})
    end)
  end)

  it("it cannot encode/decode a signed plain text token with alg=RS256 and an incorrect key", function()
    local claims = {
      test = "test",
    }
    local keys = {
      private =
[[-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANfnFz7xPmYVdJxZE7sQ5quh/XUzB5y/D5z2A7KPYXUgUP0jd5yL
Z7+pVBcFSUm5AZXJLXH4jPVOXztcmiu4ta0CAwEAAQJBAJYXWNmw7Cgbkk1+v3C0
dyeqHYF0UD5vtHLxs/BWLPI2lZO0e6ixFNI4uIuatBox1Zbzt1TSy8T09Slt4tNL
CAECIQD6PHDGtKXcI2wUSvh4y8y7XfvwlwRPU2AzWZ1zvOCbbQIhANzgMpUNOZL2
vakju4sal1yZeXUWO8FurmsAyotAx9tBAiB2oQKh4PAkXZKWSDhlI9CqHtMaaq17
Yb5geaKARNGCPQIgILYrh5ufzT4xtJ0QJ3fWtuYb8NVMIEeuGTbSyHDdqIECIQDZ
3LNCyR2ykwetc6KqbQh3W4VkuatAQgMv5pNdFLrfmg==
-----END RSA PRIVATE KEY-----]],
      public =
[[-----BEGIN PUBLIC KEY-----
MQwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANfnFz7xPmYVdJxZE7sQ5quh/XUzB5y/
D5z2A7KPYXUgUP0jd5yLZ7+pVBcFSUm5AZXJLXH4jPVOXztcmiu4ta0CAwEAAQ==
-----END PUBLIC KEY-----]],
    }
    local token = jwt.encode(claims, {alg = "RS256", keys = { private = keys.private }})
    local decodedClaims = jwt.decode(token, {keys = { public = keys.public }})
    assert.are_not.same(claims, decodedClaims)
  end)

  it("can verify a signature", function()
    local token = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJhOGZjZTFkZi1iNGFlLTRjNDEtYmFjNi1iNWJiZjI4MGMyOWMiLCJzdWIiOiI3YmZjNThlYy03N2RkLTQ4NzQtYmViZC1iYTg0MTAzMDEyNzkiLCJzY29wZSI6WyJvYXV0aC5hcHByb3ZhbHMiLCJvcGVuaWQiXSwiY2xpZW50X2lkIjoibG9naW4iLCJjaWQiOiJsb2dpbiIsImdyYW50X3R5cGUiOiJwYXNzd29yZCIsInVzZXJfaWQiOiI3YmZjNThlYy03N2RkLTQ4NzQtYmViZC1iYTg0MTAzMDEyNzkiLCJ1c2VyX25hbWUiOiJhZG1pbkBmb3Jpby5jb20iLCJlbWFpbCI6ImFkbWluQGZvcmlvLmNvbSIsImlhdCI6MTM5ODkwNjcyNywiZXhwIjoxMzk4OTQ5OTI3LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojk3NjMvdWFhL29hdXRoL3Rva2VuIiwiYXVkIjpbIm9hdXRoIiwib3BlbmlkIl19.xOa5ZpXksgoaA_XJ3yHMjlLcbSoM6XJy-e60zfyP7bRmu0EKEGZdZrl2iJVh6OTIn8z6UuvcY282C1A5LtRgpir4wqhIrphd-Mi9gfxra0pJvtydd4XqVpuNdW7GDaC43VXpvUtetmfn-YAo2jkD9G22mUuT2sFdt5NqFL7Rk4tVRILes73OWxfQpuoReWvRBik-sJXxC9ADmTuzR36OvomIrso42R8aufU2ku_zPve8IhYLvn3vHmYCt0zNZkX-jSV8YtGodr9V-dKs9na41YvGp2UxkBcV7LKoGSRELSSNJ8JLF-bjO3zYSSbT42-yeHeKfoWAeP6R7S_0c_AYRA"
    local key = [[-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3h3hbKXM40yH18djU0eM
asMIJ2jEtRn4DzJEcPvRDu+zFUzzNqSUFbD6pYIv/S+C31edIvyfi9kxMdZOKEIm
AHasLJ6PTBej+ruzIWHNf2Yse7+egXEit5bcKb3J9FOpCDHE+YjM4S9QaQT2hr30
Y7iIVcNURJn0k2T6HL+AVt0oUbupUdJjS9S5GUSQ0F74t74J9g7X4sOSTjl3RBxB
mUzfYor3w1HVwP+R0awAzSlNYZdWWJJM6aZXH76nqfv6blKTW0on12b71YWRWKYP
GxG1KwES6v5+PeLzlJDIDRcI8pl49fJYoXyasF8pskS63o9q8ibQspk+nzL9lD4E
EQIDAQAB
-----END PUBLIC KEY-----]]

    local claims, err = jwt.decode(token, {keys={public=key}})
    assert(claims, err)
  end)

  it('can verify a signature from auth0', function()
    -- This is a valid token we get from production Android app (VAN-44).
    -- And https://jwt.io shows it's signature is valid.
    local token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNXVkZLeWJQUEJVdzlFdGZ1QjlsVSJ9.eyJrcF91c2VyIjoia3JuOjppYW06Onh2cG46dXNlcjoxNmQzY2E3OS0yMGIzLTQwZWItOTc5My1lYTU3MTdhZTU0ZDMiLCJpc3MiOiJodHRwczovL2F1dGguZXhwcmVzc3Zwbi5jb20vIiwic3ViIjoiYXV0aDB8a3JuOjppYW06Onh2cG46dXNlcjoxNmQzY2E3OS0yMGIzLTQwZWItOTc5My1lYTU3MTdhZTU0ZDMiLCJhdWQiOlsiaHR0cHM6Ly93d3cuZXhwcmVzc2FwaXN2Mi5uZXQvIiwiaHR0cHM6Ly94dnBuLXByZC51cy5hdXRoMC5jb20vdXNlcmluZm8iXSwiaWF0IjoxNjkyOTMwOTg0LCJleHAiOjE2OTMwMTczODQsImF6cCI6ImdTN3Rhbm9xRWRiZHRxMnFwREt2WWFKVEZ6cTE4ZnNHIiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCJ9.M8mbJhKKgehtCvUWeoSPhZ2PsoM44ODLtLeyDemU-ZtsXeKFCv7lEcMvxQNxDEaHkoFNu3Z8ggMTeK1Yb_WOf3rX7wGWHGD53iv9y58EGE-yNW02GC7UJSn8PUi4U9T8I-M72NaXKCEZ5ayACzEycPsnUkpx2AkcjR6jxzmjWEGg_riWvUZI74thZNX_UPkMo2oXSPWNzVzcLM8REti1tajyzIsLRlUKw9cI5EGLvYdB9BSRSGORn0H2rpadSDsujxnpT6bK2g42RzDTZmLkJTS_ToLtS0SzhjHhGnDznNp00X7A-Bat8QBiDu-7ufelQEB_eCFPI1SpmZzg5eq_Vw"

    -- This is the Auth0 public key we get via this command:
    -- curl -s https://auth.expressvpn.com/pem | openssl x509 -pubkey -noout
    local key = 
[[-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqYR1c4q9SVL4s2BCbfgi
Y0Rk1W9C/oEwp4NX+1i/Sv+NPhZfPNHcj6eQNgaIPqSVuXRhFMR3CxRTqUApX2yY
mVfUbYQp/ExL2sG2O8G5fmTMXEB8dqzuKFPyp/jbcHE/egwe15Bomb8nSvkDdYXI
W18kmT2GUvbeCvY81+0ZwKjIHNsRZs9jnFudfgCx6mUWi3lBtPM9WjOlm7SN5jQl
/BgoNMS1Spw91uKBZRokQ9LxIzPahpfh2a7WQeWZrVd/3EdGVmkpdaMhiTaBpLEp
/0l1LP38B5SpeCDdIsFydKEcHvEm/rRcBpFgat0Fak2faB7RtWHVUG/vH3TPSz8e
QwIDAQAB
-----END PUBLIC KEY-----]]

  local claims, err = jwt.decode(token, {keys={public=key}})
  assert(claims, err)

  end)

  it("Is not fooled by modified tokens that claim to be unsigned", function()
    local encoded = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MTQ0NTQ3MDA3MywiZXhwIjoxNDQ1NDczNjczLCJpYXQiOjE0NDU0NzAwNzMsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9.NEbef_xsCzaLMU0Oh-Q_XLQyvF25vSIGlCcupi5-us05HFNhbTG7_2ElRmn0ew4DCBssT14GEU_8TjtcdmBkta7gCqKLF7X07UASVkL7lS_6VAu8lHGD4U4N-35AByu5gO2RQf5V3tt5WSpv2qABF4R_msF_qjZ8Ii8o_Fth6YxH6eDFgNAOCWwWwB3hvK2mJ6te9ZK04C00qc1U4xOFdO8geXaW7ohoXBCv1h8VT7sbsmyZ14ce6ASliHVCGjoXyXRGfFMQPKdJ5t4x_pSdH85MQn08nsYXIPCzMo3Fl2lFJyKbXLl3pMF1pwKpKpSxoCjbsWcjot1RmzpLbTcvfg'
    local token, err = jwt.decode(encoded)
    assert(not token)
    assert(err ~= nil)
  end)

  it("can encode and decode rs256", function()
    local keys = {
      private =
[[-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANfnFz7xPmYVdJxZE7sQ5quh/XUzB5y/D5z2A7KPYXUgUP0jd5yL
Z7+pVBcFSUm5AZXJLXH4jPVOXztcmiu4ta0CAwEAAQJBAJYXWNmw7Cgbkk1+v3C0
dyeqHYF0UD5vtHLxs/BWLPI2lZO0e6ixFNI4uIuatBox1Zbzt1TSy8T09Slt4tNL
CAECIQD6PHDGtKXcI2wUSvh4y8y7XfvwlwRPU2AzWZ1zvOCbbQIhANzgMpUNOZL2
vakju4sal1yZeXUWO8FurmsAyotAx9tBAiB2oQKh4PAkXZKWSDhlI9CqHtMaaq17
Yb5geaKARNGCPQIgILYrh5ufzT4xtJ0QJ3fWtuYb8NVMIEeuGTbSyHDdqIECIQDZ
3LNCyR2ykwetc6KqbQh3W4VkuatAQgMv5pNdFLrfmg==
-----END RSA PRIVATE KEY-----]],
      public =
[[-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANfnFz7xPmYVdJxZE7sQ5quh/XUzB5y/
D5z2A7KPYXUgUP0jd5yLZ7+pVBcFSUm5AZXJLXH4jPVOXztcmiu4ta0CAwEAAQ==
-----END PUBLIC KEY-----]],
    }
    local claims = {
      test = "test",
      longClaim = "iubvn1oubv91henvicuqnw93bn19u  ndij npkhabsdvlb23iou4bijbandlivubhql3ubvliuqwdbnvliuqwhv9ulqbhiulbiluabsdvuhbq9urbv9ubqubxuvbu9qbdshvuhqniuhv9uhbfq9uhr89hqu9ebnv9uqhu9rbvp9843$#BVCo²¸´no414i"
    }
    local token = jwt.encode(claims, {alg = "RS256", keys = keys})
    local decodedClaims, err = jwt.decode(token, {alg = "RS256", keys = keys})
    if not decodedClaims then error(err) end
    assert.are.same(claims, decodedClaims)
  end)

    it("does not panic when key is invalid in rs256", function()
    local keys = {
      private =
[[-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANfnFz7xPmYVdJxZE7sQ5quh/XUzB5y/D5z2A7KPYXUgUP0jd5yL
Z7+pVBcFSUm5AZXJLXH4jPVOXztcmiu4ta0CAwEAAQJBAJYXWNmw7Cgbkk1+v3C0
dyeqHYF0UD5vtHLxs/BWLPI2lZO0e6ixFNI4uIuatBox1Zbzt1TSy8T09Slt4tNL
CAECIQD6PHDGtKXcI2wUSvh4y8y7XfvwlwRPU2AzWZ1zvOCbbQIhANzgMpUNOZL2
vakju4sal1yZeXUWO8FurmsAyotAx9tBAiB2oQKh4PAkXZKWSDhlI9CqHtMaaq17
Yb5geaKARNGCPQIgILYrh5ufzT4xtJ0QJ3fWtuYb8NVMIEeuGTbSyHDdqIECIQDZ
3LNCyR2ykwetc6KqbQh3W4VkuatAQgMv5pNdFLrfmg==
-----END RSA PRIVATE KEY-----]],
      public =
[[-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANfnFz7xPmYVdJxZE7sQ5quh/XUzB5y/
D5z2A7KPYXUgUP0jd5yLZ7+pVBcFSUm5AZXJLXH4jPVOXztcmiu4ta0CAwEAAQ==
-----END PUBLIC KEY-----]],
    }
    local invalid_key = "a really invalid key"
    local data = {
      test = "test",
    }
    local token = jwt.encode(data, {alg = "RS256", keys = keys})
    assert.has.no.error(function ()
      local result, err = jwt.decode(token, {keys = {public = invalid_key }})
      assert.is_nil(result)
      assert.is_not_nil(err)
    end)
  end)

  it("panics when failing to generate a signature", function()
    local invalid_key = "a really invalid key"
    local data = {
      test = "test",
    }
    assert.has_error(function ()
      local token, err = jwt.encode(data, {alg = "RS256", keys = { private = invalid_key }})
      assert.is_nil(token)
      assert.is_not_nil(err)
    end)
  end)

  it("should return an error instead of panic when decoding a token with non-allowed algorithm", function()
    local claim = {
      iss = "joe",
      exp = 1300819380,
      ["http://example.com/is_root"] = true
    }
    local token = jwt.encode(claim)
    assert.has.no.error(function ()
      local decoded, err = jwt.decode(token, {alg = "RS256"})
      assert.is_nil(decoded)
      assert.is_not_nil(err)
      assert.are.equals("Jwt uses a disallowed algorithm", err)
    end)
  end)
end)
