-module(auth_hub_app).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').
-behaviour(application).

-include("auth_hub.hrl").

-export([start/2, stop/1]).


start(normal, _StartArgs) ->
    opts = ets:new(opts, [named_table, public]),
    sids_cache = ets:new(sids_cache, [named_table, public]),
    subsys_cache = ets:new(subsys_cache, [named_table, public]),

    {ok, Salt} = application:get_env(auth_hub, salt),
    true = ets:insert(opts, {salt, Salt}),

    % ----------
    {ok, Port} = application:get_env(auth_hub, listen_port),
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/api/users/info",                   auth_hub_req_api, [<<"/users/info">>]},
            {"/api/users",                        auth_hub_req_api, [<<"/users">>]},
            {"/api/roles/change",                 auth_hub_req_api, [<<"/roles/change">>]},
            {"/api/allow/subsystems/roles/info",  auth_hub_req_api, [<<"/allow/subsystems/roles/info">>]},
            {"/api/allow/roles/change",           auth_hub_req_api, [<<"/allow/roles/change">>]},
            {"/api/allow/subsystems/change",      auth_hub_req_api, [<<"/allow/subsystems/change">>]},

            {"/session/open",         auth_hub_req_sid, [open_session]},
            {"/session/check",        auth_hub_req_sid, [check_sid]},

            {"/authorization/roles",  auth_hub_req_auth, [get_roles]},
            {"/identification/login", auth_hub_req_auth, [get_ldap]}
        ]}
    ]),
    {ok, _} = cowboy:start_clear(http, [{port, Port}], #{
        env => #{dispatch => Dispatch}
    }),
    auth_hub_sup:start_link();

start({takeover, NodeCluster}, StartArg) ->
    _Pid = spawn(NodeCluster, auth_hub_app, stop, [null]), %% delete cluster run before execute main node auth_hub
    ok = timer:sleep(1000),                                  %% wait wile deleted
    start(normal, StartArg).


stop(_State) ->
    ok = cowboy:stop_listener(http).

