function auth_user(username, password)
	uname_len = string.len(username)
	passw_len = string.len(password)

	if uname_len == passw_len then
		return true
	else
		return false
	end

end




ips = {}

ip_second = 0
ip_count = 3


function get_ip_for_session(session)
	if not ips[session] then
		if ip_count == 254 then
			ip_second = ip_second + 1
			ip_count = 3
		end
		ips[session] = internal_ip .. "." .. tostring(ip_second) .. "." .. tostring(ip_count)
		ip_count = ip_count + 1
	end

	return ips[session]
end

function return_ip_for_session(session)
	if ips[session] then
		ips[session] = nil
	end
end

function get_peer_ip()
	return internal_ip .. ".0.2"
end

function get_dns_ip()
  return "8.8.8.8"
end


