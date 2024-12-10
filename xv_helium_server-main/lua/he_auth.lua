require('he_utils')

-- Simple auth system test
-- Used for comparing credentials
local crypt = require("crypt")

-- SQLite3 library
local sqlite3 = require("lsqlite3")

-- Open up the credentials database for future use
local db = nil
local stmt = nil

function load_db()
    if stmt ~= nil then
        stmt:finalize()
    end

    if db ~= nil then
        db:close()
    end

    db = sqlite3.open(auth_path)
    stmt = assert(db:prepare("SELECT encrypted_credentials FROM vpn_accounts WHERE username = ? LIMIT 1"))
end

function unload_db()
    if stmt ~= nil then
        stmt:finalize()
        stmt = nil
    end

    if db ~= nil then
        db:close()
        db = nil
    end
end

function auth_user(username, password)
    load_db()
    stmt:bind_values(username)

    retval = false

    for row in stmt:nrows() do
        retval = crypt.check(password, row.encrypted_credentials)
    end

    unload_db()

    -- No user found?
    return retval
end

function valid_user(username)
    load_db()
    stmt:bind_values(username)

    retval = false

    for row in stmt:nrows() do
        retval = true
    end

    unload_db()

    return retval
end

function allocate_ip()
    return free_ips:allocate()
end

function release_ip(ip)
    return free_ips:release(ip)
end

-- Initialize the inside ip pool on load
free_ips, err = make_ip_pool(internal_ip, false)
