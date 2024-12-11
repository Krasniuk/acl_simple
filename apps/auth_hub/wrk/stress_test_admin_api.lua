--author('Mykhailo Krasniuk <miha.190901@gmail.com>').


--========= Variables =========--

local Sid = "3079a1b8b7e911efbd8a18c04d540e8a"

local actions = {
--    "create_user",
    "get_all_users_info",
    "get_allow_subsystems_roles"
}


--========= Export functions =========--

function request()
    local param = {method = nil, url = nil, headers = nil, body = nil}
    local Action = actions[math.random(1, #actions)]
    if Action == "get_all_users_info" then
        param = {method = "GET", url = "/api/users/info", headers = {["sid"] = Sid}, body = nil}
    elseif Action == "get_allow_subsystems_roles" then
        param = {method = "GET", url = "/api/allow/subsystems/roles/info", headers = {["sid"] = Sid}, body = nil}
        --   elseif Action == "create_users" then
        --       Rand = math.random(1, 1000000)
        --       param = {method = "POST", url = "/api/users", headers = {["sid"] = Sid}, body = [[
        --        {
        --            "method": "create_users",
        --           "users": [
        --              {
        --                  "login": "stressTest_]].. Rand ..[["}}',
        --                  "pass": "stressTest_]].. Rand ..[["
        --              }
        --         ]
        --        }
        --        ]]}
    end

    return wrk.format(param.method, param.url, param.headers, param.body)
end

function response(Status, headers, Body)
    if Status ~= 200 then
        io.write('status ' .. Status .. ', body ' .. Body .. '\n')
    end
end

--========= Local functions =========--


