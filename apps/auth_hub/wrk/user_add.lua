
request = function()
    path = "/"
    wrk.headers["Content-Type"] = "application/json; charset=utf-8"
    local user = 'mike_test' --.. tostring( math.random(0, 100000))
    wrk.body = '{"method":"user_add", "user":"'.. user ..'"}'
   -- a = a + 1
    return wrk.format("POST", path)
end

response = function(status, headers, body)
    io.write('----------------------------\n')
    io.write('status = ' .. status ..'\n')
    io.write('body = '.. body ..'\n')
end
