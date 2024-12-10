require('he_utils')

-- Token based authentication
local jwt = require('jwt')

---All auth token public keys
local global_keys = {}
local global_audiences = {}
local global_entitlements = {}

---Authenticate user with access token and a single public key
---@param token string A JWT access token
---@param pubkey string Public key
---@param leeway integer|nil Define the leeway in seconds
---@return boolean result Return true if the access token is valid
---@return string|nil reason Return false and the reason if the authentication failed
---@note This function is deprecated and it's provided for backward-compatibile only.
function auth_user_with_token_and_key(token, pubkey, leeway)
    if is_nil_or_empty(token) then
        return false, "empty token"
    end
    if is_nil_or_empty(pubkey) then
        return false, "empty pubkey"
    end

    -- Default leeyway is 300 seconds
    local leeway = leeway or 300

    -- Decode the JWT token
    local obj, err = jwt.decode(token, {
        alg = "RS256",
        keys = {
            public = pubkey
        }
    })
    if err then
        return false, err
    end

    -- Reject if the token is not valid yet
    if obj.nbf and obj.nbf > os.time() + leeway then
        return false, "not valid yet"
    end

    -- Reject if the token has expired
    if obj.exp and obj.exp < os.time() - leeway then
        return false, "expired"
    end

    -- Token is valid
    return true, nil
end

---Authenticate user with access token
---@param token string A JWT access token
---@param options table|nil Authentication options
---@return boolean result Return true if the access token is valid
---@return string|nil reason Return false and the reason if the authentication failed
function auth_user_with_token(token, options)
    if is_nil_or_empty(token) then
        return false, "empty token"
    end

    -- Decode the token header first
    local header = jwt.decode_header(token)
    if is_nil_or_empty(header) then
        return false, "invalid token"
    end

    -- Reject if the token's algorithm is not RS256
    if header.alg ~= 'RS256' then
        return false, "invalid algorithm"
    end

    -- Default leeyway is 300 seconds
    local opts = options or {
        leeway = 300
    }
    local leeway = opts.leeway or 300

    -- Find the public key for the token
    local key = global_keys[header.kid]
    if is_nil_or_empty(key) then
        return false, "public key not set"
    end

    -- Decode the JWT token
    local obj, err = jwt.decode(token, {
        alg = "RS256",
        keys = {
            public = key.pub
        }
    })
    if err then
        return false, err
    end

    -- Reject if the token is not valid yet
    if obj.nbf and obj.nbf > os.time() + leeway then
        return false, "not valid yet"
    end

    -- Reject if the token has expired
    if obj.exp and obj.exp < os.time() - leeway then
        return false, "expired"
    end

    -- Reject if the token doesn't have 'aud' claim
    if is_nil_or_empty(obj.aud) then
        return false, "missing aud"
    end

    -- Reject if the token's aud claims doesn't match any of the key's audiences
    if type(global_audiences) == "table" and #global_audiences > 0 then
        local found = false
        if type(obj.aud) == "table" then
            for _, aud in ipairs(obj.aud) do
                if table.contains(global_audiences, aud) then
                    found = true
                    break
                end
            end
        elseif type(obj.aud) == "string" then
            found = table.contains(global_audiences, obj.aud)
        end
        if not found then
            return false, "invalid audience"
        end
    end

    -- Reject if the token's entitlements doesn't match the key's entitlements
    -- https://polymoon.atlassian.net/wiki/spaces/KPL/pages/3084749334/JSON+Web+Token+JWT#Connection-Authorization-Token-(CAT)
    local key_ent = ""
    local token_ent = nil
    if type(global_entitlements) == "table" and #global_entitlements > 0 then
        if is_nil_or_empty(obj.entitlements) then
            return false, "missing entitlements"
        end

        for _, ent in ipairs(global_entitlements) do
            if type(obj.entitlements) == "table" then
                local elem = obj.entitlements[ent]
                if not is_nil_or_empty(elem) then
                    key_ent = ent
                    token_ent = elem
                    break
                end
            elseif type(obj.entitlements) == "string" then
                if string.sub(obj.entitlements, 1, #ent) == ent then
                    key_ent = ent
                    token_ent = obj.entitlements
                    break
                end
            end
        end
        if is_nil_or_empty(token_ent) then
            return false, "invalid entitlements"
        end
    end

    -- Check DIP token
    -- https://polymoon.atlassian.net/wiki/spaces/KPL/pages/3084749334/JSON+Web+Token+JWT#Dedicated-IP-Authorization-Token-(DAT)
    if not is_nil_or_empty(opts.dip) then
        -- Check the key of the matching entitlement
        if not key_ent:match(".*.vpn.dip.details") then
            return false, "invalid dip entitlement"
        end

        -- Find the token's dip entitlements
        if token_ent == nil or type(token_ent) ~= "table" then
            return false, "invalid dip entitlements"
        end

        -- The entitlement must contain the given destination ip
        local token_dip = token_ent.ip
        if token_dip == nil or token_dip == "" or type(token_dip) ~= "string" then
            return false, "invalid dip entitlements"
        end

        if token_dip ~= opts.dip then
            return false, "invalid dip"
        end
    end

    -- Token is valid
    return true, nil
end

---Authenticate user with a DIP connection token
---@param token string A JWT access token
---@param dip string The destination ip address of the connection. It must be exactly the same as the ip embedded in the token's DIP entitlement.
---@param leeway integer|nil Define the leeway in seconds
---@return boolean result Return true if the access token is valid
---@return string|nil reason Return false and the reason if the authentication failed
function auth_user_with_dip_token(token, dip, leeway)
    if is_nil_or_empty(dip) then
        return false, "invalid destination ip"
    end
    return auth_user_with_token(token, {
        dip = dip,
        leeway = leeway or nil
    })
end

---Load public key pem from the given file at path
---@param path string: The path to the public key file
---@return string path The string contains the public key
function load_pubkey_from_path(path)
    local f = io.open(path, "rb")
    if not f then
        return nil
    end
    local pubkey = f:read "*a"
    f:close()
    return pubkey
end

---Load all auth token keys from given config file
---@param path string: Path to the auth token config file
---@return string|nil error The error reason if the operation failed.
function load_all_auth_token_keys(path)
    local config = load_table_from_json_file(path)
    if is_nil_or_empty(config) then
        return "error loading auth token config"
    end

    global_audiences = config.audiences
    global_entitlements = config.entitlements

    local keys = {}
    for kid, key in pairs(config.auth_token_public_keys) do
        if key.path and not key.pub then
            local pub = load_pubkey_from_path(key.path)
            if not is_nil_or_empty(pub) then
                key.pub = pub
            end
        end
        keys[kid] = key
    end

    global_keys = keys
end
