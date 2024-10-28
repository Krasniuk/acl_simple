
request = function()
    path = "/"
    wrk.headers["Content-Type"] = "application/json; charset=utf-8"
    local user = 'mike_test'
    wrk.body = '{"method":"roles_add", "user":"'.. user ..'", "roles":["write", "read", "exec"]}'
    return wrk.format("POST", path)
end

response = function(status, headers, body)
    io.write('----------------------------\n')
    io.write('status = ' .. status ..'\n')
    io.write('body = '.. body ..'\n')
end