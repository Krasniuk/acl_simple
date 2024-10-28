-module(auth_hub_timers).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').
-behavior(gen_server).

-include("auth_hub.hrl").

-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
-export([refresh_cache/0]).

% ====================================================
% Users functions
% ====================================================

start_link() ->
    gen_server:start_link(?MODULE, [], []).

refresh_cache() ->
    [{_, Pid}] = ets:lookup(auth_hub, auth_hub_timers),
    _Timer = erlang:send_after(10, Pid, refresh_cache),
    ok.


% ====================================================
% Inverse functions
% ====================================================

init([]) ->
    true = ets:insert(auth_hub, [{auth_hub_timers, self()}]),
    {ok, PauseTime} = application:get_env(auth_hub, timer_cache),
    {ok, PauseAllowRoles} = application:get_env(auth_hub, timer_allow_roles),
    TCache = erlang:send_after(200, self(), {timer_cache, PauseTime}),
    TAllowRoles = erlang:send_after(205, self(), {timer_allow_roles, PauseAllowRoles}),
    {ok, #{timer_cache => TCache,
           timer_allow_roles => TAllowRoles
    }}.

terminate(_, _State) ->
    ok.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
handle_call(_Data, _From, State) ->
    {reply, unknown_req, State}.
handle_cast(_Data, State) ->
    {noreply, State}.

handle_info({timer_cache, PauseTime}, #{timer_cache := T} = State) ->
    _ = erlang:cancel_timer(T),
    Timer = case timer_cache_handler() of
                {error, _} ->
                    erlang:send_after(2000, self(), {timer_cache, PauseTime});
                {MapCache, MapPassHash} ->
                    true = ets:insert(auth_hub, [{server_cache, MapCache}]),
                    true = ets:insert(auth_hub, [{customer_passhash, MapPassHash}]),
                    erlang:send_after(PauseTime, self(), {timer_cache, PauseTime})
            end,
    {noreply, State#{timer_cache := Timer}};
handle_info({timer_allow_roles, PauseTime}, #{timer_allow_roles := T} = State) ->
    _ = erlang:cancel_timer(T),
    Timer = case allow_roles_handler() of
                {error, _} ->
                    erlang:send_after(2000, self(), {timer_allow_roles, PauseTime});
                List ->
                    true = ets:insert(auth_hub, [{allow_roles, List}]),
                    erlang:send_after(PauseTime, self(), {timer_allow_roles, PauseTime})
            end,
    {noreply, State#{timer_allow_roles := Timer}};
handle_info(refresh_cache, State) ->
    {Cache, CachePassHash} = timer_cache_handler(),
    true = ets:insert(auth_hub, [{server_cache, Cache}]),
    true = ets:insert(auth_hub, [{customer_passhash, CachePassHash}]),
    AllowRoles = allow_roles_handler(),
    true = ets:insert(auth_hub, [{allow_roles, AllowRoles}]),
    {noreply, State};
handle_info(_Data, State) ->
    {noreply, State}.


% ====================================================
% Help-functions for inverse functions
% ====================================================

-spec allow_roles_handler() -> list() | {error, any()}.
allow_roles_handler() ->
    case auth_hub_pg:select("get_allow_roles", []) of
        {error, Error} ->
            {error, Error};
        {ok, _, AllowRoles} ->
            handler_convert_to_map(AllowRoles)
    end.

-spec timer_cache_handler() -> {error, any()} | {map(), map()}.
timer_cache_handler() ->
    case auth_hub_pg:select("get_all_users", []) of
        {error, Error} ->
            {error, Error};
        {ok, _, Users} ->
            convert_to_map(Users, #{}, #{})
    end.

-spec convert_to_map(list(), #{}, #{}) -> {map(), map()}.
convert_to_map([], MapCache, MapPassHash) ->
    {MapCache, MapPassHash};
convert_to_map([{Name, PassHash} | T], MapCache, MapPassHash) ->
    {ok, _, RolesList_Dirty} = auth_hub_pg:select("get_roles_by_name", [Name]),
    RolesList = handler_convert_to_map(RolesList_Dirty),
    MapCache1 = MapCache#{Name => RolesList},
    MapPassHash1 = MapPassHash#{Name => jsone:decode(PassHash)},
    convert_to_map(T, MapCache1, MapPassHash1).


%% ------------------------------------------

-spec handler_convert_to_map(list()) -> list().
handler_convert_to_map([]) ->
    [];
handler_convert_to_map([{Role} | T]) ->
    [Role | handler_convert_to_map(T)].
