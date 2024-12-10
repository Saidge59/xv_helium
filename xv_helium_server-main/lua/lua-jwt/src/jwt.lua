local meta    = {}
local data    = {}

local json    = require 'jwt.utils'.json
local basexx  = require 'basexx'
local jws     = require 'jwt.jws'
local jwe     = require 'jwt.jwe'
local plain   = require 'jwt.plain'

local function getJwt(options)
  if options and options.alg and options.alg ~= "none" then
    if options.enc then
      return jwe
    else
      return jws
    end
  else
    return plain
  end
end

function meta:__metatable()
  return false
end

function meta:__index(key)
  return data[key]
end

local function header(options)
  if options then
    return {
      alg = options.alg,
      enc = options.enc,
      iss = options.iss,
      aud = options.aud,
      sub = options.sub,
      kid = options.kid,
    }
  end
  return {
    alg = "none",
  }
end

function data.encode(claims, options)
  local jwt       = getJwt(options)
  local header    = header(options)
  local token, err = jwt:encode(header, claims, options)
  if not token then return nil, err end
  return token
end

function data.decode_header(str)
  if not str then return nil, "Parameter 1 cannot be nil" end
  local dotFirst = str:find(".", nil, true)
  if not dotFirst then return nil, "Invalid token" end
  return json.decode((basexx.from_url64(str:sub(1,dotFirst-1))))
end

function data.decode(str, options)
  if not str then return nil, "Parameter 1 cannot be nil" end
  local dotFirst = str:find(".", nil, true)
  if not dotFirst then return nil, "Invalid token" end
  local header = data.decode_header(str)
  if not header then return nil, "Invalid token" end

  if options and options.alg and options.alg ~= header.alg then
    return nil, "Jwt uses a disallowed algorithm"
  end

  return getJwt(header):decode(header, str, options)
end

function meta:__newindex(key)
  error('Read Only')
end

return setmetatable({}, meta)
