-module(auth_hub_app).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').
-behaviour(application).

-include("auth_hub.hrl").

-export([start/2, stop/1]).


start(normal, _StartArgs) ->
    auth_hub = ets:new(auth_hub, [set, public, named_table]),
    opts = ets:new(opts, [named_table, public]),
    sids_cache = ets:new(sids_cache, [named_table, public]),
    subsys_cache = ets:new(subsys_cache, [named_table, public]),
    true = ets:insert(auth_hub, [{server_cache, #{}}]),

    {ok, Salt} = application:get_env(auth_hub, salt),
    true = ets:insert(opts, {salt, Salt}),

    % ----------
    {ok, Port} = application:get_env(auth_hub, listen_port),
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/admin", auth_hub_admin_handler, []},
            {"/session/open", auth_hub_sid_handler, [open_session]},
            {"/session/check", auth_hub_sid_handler, [check_sid]},
            {"/authorization/roles", auth_hub_auth_handler, [get_roles]},
            {"/identification/login", auth_hub_auth_handler, [get_ldap]}
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

