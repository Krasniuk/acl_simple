request = function()
    path = "/customer"
    wrk.headers["Content-Type"] = "application/json; charset=utf-8"
    wrk.body = '{"auth":{"login":"lion_test","passhash":[113,16,237,164,208,158,6,42,165,228,163,144,176,165,114,172,13,44,2,32]},"parameters":{"method":"get_roles"}}'
    return wrk.format("POST", path)
end

response = function(status, headers, body)
    --io.write('----------------------------\n')
    --io.write('status = ' .. status ..'\n')
    --io.write('body = '.. body ..'\n')
end