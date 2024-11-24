-module(auth_hub_timers).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').
-behavior(gen_server).

-include("auth_hub.hrl").

-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

% ====================================================
% Users functions
% ====================================================

start_link() ->
    gen_server:start_link(?MODULE, [], []).


% ====================================================
% Inverse functions
% ====================================================

-spec init([]) -> {ok, map()}.
init([]) ->
    WorkerPid = self(),
    TInitialization = erlang:send_after(200, WorkerPid, initialization),
    TDelSids = erlang:send_after(5000, WorkerPid, delete_legacy_sids),
    {ok, #{
        initialization_t => TInitialization,
        delete_legacy_sids_t => TDelSids,
        worker_pid => WorkerPid
    }}.

handle_call(_Data, _From, State) -> {reply, unknown_req, State}.
handle_cast(_Data, State) -> {noreply, State}.

-spec handle_info(atom(), map()) -> {atom(), map()}.
handle_info(initialization, #{initialization_t := OldTimer, worker_pid := WorkerPid} = State) ->
    _ = erlang:cancel_timer(OldTimer),
    NewTimer = try poolboy:checkout(pg_pool, true, 1000) of
                   full ->
                       ?LOG_ERROR("download_sids no workers in pg_pool", []),
                       erlang:send_after(2000, WorkerPid, initialization);
                   PgPid ->
                       DbRespSid = auth_hub_pg:sql_req_not_prepared(PgPid, ?SQL_INIT_SIDS, []),
                       DbRespSubSys = auth_hub_pg:sql_req_not_prepared(PgPid, ?SQL_INIT_SUBSYS, []),
                       ok = poolboy:checkin(pg_pool, PgPid),
                       save_to_ets(DbRespSid, DbRespSubSys, WorkerPid)
               catch
                   exit:{timeout, Reason} ->
                       ?LOG_ERROR("download_sids no workers in pg_pool ~p", [Reason]),
                       erlang:send_after(2000, WorkerPid, initialization)
               end,
    {noreply, State#{initialization_t := NewTimer}};
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
    NewTimer = erlang:send_after(600000, WorkerPid, delete_legacy_sids),
    {noreply, State#{delete_legacy_sids_t := NewTimer}};
handle_info(_Data, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
terminate(_, _State) ->
    ok.

%% ====================================================
%% Help-functions for inverse functions
%% ====================================================

-spec save_to_ets(list(), list(), pid()) -> null | reference().
save_to_ets(_, {error, ReasonSubSys}, WorkerPid) ->
    ?LOG_ERROR("initialization get_subsys internal error ~p", [ReasonSubSys]),
    erlang:send_after(2000, WorkerPid, initialization);
save_to_ets({error, ReasonSid}, _, WorkerPid) ->
    ?LOG_ERROR("initialization get_sids internal error ~p", [ReasonSid]),
    erlang:send_after(2000, WorkerPid, initialization);
save_to_ets({ok, _, DbRespSid}, {ok, _, DbRespSubSys}, _WorkerPid) ->
    EtsSids = parse_sids(DbRespSid),
    true = ets:insert(sids_cache, EtsSids),
    true = ets:insert(subsys_cache, DbRespSubSys),
    ?LOG_DEBUG("Success initialization sids_catche, subsys_cache from db", []),
    null.

-spec parse_sids(list()) -> list().
parse_sids([]) -> [];
parse_sids([{Sid, Login, RolesTuple, {Date, {H, M, S}}} | T]) ->
    [{Sid, Login, RolesTuple, {Date, {H, M, round(S)}}} | parse_sids(T)].

-spec delete_sids(atom(), list()) -> ok.
delete_sids(_, []) -> ok;
delete_sids(Table, [Sid | T]) ->
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

