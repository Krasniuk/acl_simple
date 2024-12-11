--author('Mykhailo Krasniuk <miha.190901@gmail.com>').


--========= Variables =========--

local Sid = "07823976b7e111ef8cf318c04d540e8a"

local scenarios = {
    -- get_ldap
    {method = "GET",  url = "/identification/login", headers = {["sid"] = Sid}, body = nil},
    -- check_sid
    {method = "GET",  url = "/session/check?sid=" .. Sid, headers = {}, body = nil},
    -- get_roles
    {method = "POST", url = "/authorization/roles", headers = {["sid"] = Sid}, body = '{"subsystem": "authHub"}'}
}


--========= Export functions =========--

function request()
    param = scenarios[math.random(1, #scenarios)]
    return wrk.format(param.method, param.url, param.headers, param.body)
end

function response(Status, headers, Body)
    if Status ~= 200 then
        io.write('status ' .. Status .. ', body ' .. Body .. '\n')
    end
end

--========= Local functions =========--


