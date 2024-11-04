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
    WorkerPid = self(),
    TSetCache = erlang:send_after(200, WorkerPid, download_sids),
    TDelSids = erlang:send_after(1000, WorkerPid, delete_legacy_sids),


    % true = ets:insert(auth_hub, [{auth_hub_timers, self()}]),
    % {ok, PauseTime} = application:get_env(auth_hub, timer_cache),
    % {ok, PauseAllowRoles} = application:get_env(auth_hub, timer_allow_roles),
    %  TCache = erlang:send_after(200, self(), {timer_cache, PauseTime}),
    % TAllowRoles = erlang:send_after(205, self(), {timer_allow_roles, PauseAllowRoles}),
    {ok, #{%timer_cache => TCache,
        %timer_allow_roles => TAllowRoles,
        download_sids_t => TSetCache,
        delete_legacy_sids_t => TDelSids,
        worker_pid => WorkerPid
    }}.

terminate(_, _State) ->
    ok.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
handle_call(_Data, _From, State) ->
    {reply, unknown_req, State}.
handle_cast(_Data, State) ->
    {noreply, State}.


handle_info(download_sids, #{download_sids_t := OldTimer, worker_pid := WorkerPid} = State) ->
    _ = erlang:cancel_timer(OldTimer),
    NewTimer = case auth_hub_pg:select("download_sids", []) of
                   {error, Reason} ->
                       ?LOG_ERROR("download_sids db error, reason ~p", [Reason]),
                       erlang:send_after(2000, WorkerPid, download_sids);
                   {ok, _, EtsTable} ->
                       EtsTable1 = parse_ets_table(EtsTable),
                       true = ets:insert(sids_cache, EtsTable1),
                       ?LOG_DEBUG("Success download sids_catche from db", []),
                       OldTimer
               end,
    {noreply, State#{download_sids_t := NewTimer}};
handle_info(delete_legacy_sids, #{delete_legacy_sids_t := OldTimer, worker_pid := WorkerPid} = State) ->
    _ = erlang:cancel_timer(OldTimer),
    SidsCache = ets:tab2list(sids_cache),
    case select_legacy_sids(SidsCache, calendar:local_time()) of
        [] ->
            ok;
        SidsDelete ->
            LenDelSids = length(SidsDelete),
            Sql = generate_sql(flag_first, LenDelSids, ?SQL_DELETE_SIDS),
            case auth_hub_pg:sql_req_not_prepared(Sql, SidsDelete) of
                {ok, LenDelSids} ->
                    delete_sids(sids_cache, SidsDelete),
                    ?LOG_DEBUG("delete_legacy_sids delete sids ~p", [SidsDelete]);
                {ok, OtherDeleted} ->
                    ?LOG_WARNING("delete_legacy_sids delete not all sids in db ~p, ~p", [OtherDeleted, LenDelSids]),
                    delete_sids(sids_cache, SidsDelete),
                    ?LOG_DEBUG("delete_legacy_sids delete sids ~p", [SidsDelete]);
                {error, Reason} ->
                    ?LOG_ERROR("delete_legacy_sids can't send req, ~p", [Reason])
            end
    end,
    NewTimer = erlang:send_after(120000, WorkerPid, delete_legacy_sids),
    {noreply, State#{download_sids_t := NewTimer}};

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

-spec parse_ets_table(list()) -> list().
parse_ets_table([]) -> [];
parse_ets_table([{Sid, Login, RolesTuple, {Date, {H, M, S}}}|T]) ->
    [{Sid, Login, RolesTuple, {Date, {H, M, round(S)}}}| parse_ets_table(T)].

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

-spec delete_sids(atom(), list()) -> ok.
delete_sids(_, []) -> ok;
delete_sids(Table, [Sid|T]) ->
    true = ets:delete(Table, Sid),
    delete_sids(Table, T).

-spec select_legacy_sids(EtsTab :: list(), TsNow :: tuple()) -> Sids :: list().
select_legacy_sids([], _) -> [];
select_legacy_sids([{Sid, _Login, _RolesTuple, Ts} | T], TsNow) ->
    GSecSid = calendar:datetime_to_gregorian_seconds(Ts),
    GSecNow = calendar:datetime_to_gregorian_seconds(TsNow),
    case GSecNow >= GSecSid of
        true ->
            [Sid | select_legacy_sids(T, TsNow)];
        false ->
            select_legacy_sids(T, TsNow)
    end.

-spec generate_sql(flag_first|null, integer(), list()) -> list().
generate_sql(_Flag, 0, Sql) -> Sql;
generate_sql(flag_first, SidsNum, Sql) ->
    Sql1 = Sql ++ " sid=$" ++ integer_to_list(SidsNum),
    generate_sql(null, SidsNum - 1, Sql1);
generate_sql(Flag, SidsNum, Sql) ->
    Sql1 = Sql ++ " or sid=$" ++ integer_to_list(SidsNum),
    generate_sql(Flag, SidsNum - 1, Sql1).

%% ------------------------------------------

-spec handler_convert_to_map(list()) -> list().
handler_convert_to_map([]) ->
    [];
handler_convert_to_map([{Role} | T]) ->
    [Role | handler_convert_to_map(T)].
