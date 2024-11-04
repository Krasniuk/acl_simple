-module(auth_hub_pg).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').
-behavior(gen_server).

-include("auth_hub.hrl").

-export([start_link/1]). % Export for poolboy
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]). % Export for gen_server
-export([select/2, insert/2, delete/2, sql_req_not_prepared/2, sql_req_not_prepared/3, get_roles/1]).

% ====================================================
% Clients functions
% ====================================================

start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

-spec get_roles(binary()) -> null | map().
get_roles(Login) ->
    case auth_hub_pg:select("get_roles", [Login]) of
        {error, Reason} ->
            ?LOG_ERROR("Get roles from db error, ~p", [Reason]),
            null;
        {ok, _Colon, RespDb} ->
            convert_roles_from_db(RespDb, #{})
    end.

-spec convert_roles_from_db(list(), map()) -> map().
convert_roles_from_db([], Result) -> Result;
convert_roles_from_db([{SubSys, Role}|T], Result) ->
    case maps:get(SubSys, Result, undefined) of
        undefined ->
            convert_roles_from_db(T, Result#{SubSys => [Role]});
        Roles ->
            Roles1 = Roles ++ [Role],
            convert_roles_from_db(T, Result#{SubSys := Roles1})
    end.

-spec select(list(), list()) -> {ok, PropListAtr :: list(), PropListResp :: list()} | {error, Reason :: tuple()|no_connect}.
select(Statement, Args) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {error, {timeout_pull, <<"too many requests">>}};
        WorkerPid ->
            Reply = gen_server:call(WorkerPid, {select, Statement, Args}),
            ok = poolboy:checkin(pg_pool, WorkerPid),
            Reply
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("Error, no workers in pg_pool ~p", [Reason]),
            {error, {timeout_pull, <<"too many requests">>}}
    end.

-spec insert(list(), list()) -> {ok, integer()} | {error, Reason :: tuple()|no_connect}.
insert(Statement, Args) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {error, {timeout_pull, <<"too many requests">>}};
        WorkerPid ->
            Reply = gen_server:call(WorkerPid, {insert, Statement, Args}),
            ok = poolboy:checkin(pg_pool, WorkerPid),
            Reply
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("Error, no workers in pg_pool ~p", [Reason]),
            {error, {timeout_pull, <<"too many requests">>}}
    end.

delete(Statement, Args) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {error, {timeout_pull, <<"too many requests">>}};
        WorkerPid ->
            Reply = gen_server:call(WorkerPid, {delete, Statement, Args}),
            ok = poolboy:checkin(pg_pool, WorkerPid),
            Reply
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("Error, no workers in pg_pool ~p", [Reason]),
            {error, {timeout_pull, <<"too many requests">>}}
    end.

-spec sql_req_not_prepared(list(), list()) -> {ok, list()} | {error, term()} | {error, {timeout_pull, binary()}}.
sql_req_not_prepared(Sql, Args) ->
    try poolboy:checkout(pg_pool, true, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {error, {timeout_pull, <<"too many requests">>}};
        WorkerPid ->
            DbResp = sql_req_not_prepared(WorkerPid, Sql, Args),
            ok = poolboy:checkin(pg_pool, WorkerPid),
            DbResp
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("Error, no workers in pg_pool ~p", [Reason]),
            {error, {timeout_pull, <<"too many requests">>}}
    end.

-spec sql_req_not_prepared(pid(), list(), list()) -> {ok, list()} | {error, term()}.
sql_req_not_prepared(WorkerPid, Sql, Args) ->
    gen_server:call(WorkerPid, {sql_req_not_prepared, Sql, Args}).


% ====================================================
% Inverse functions
% ====================================================

init(Args) ->
    TConn = erlang:send_after(10, self(), connect),
    {ok, #{connect_arg => Args,
        timer_connect => TConn,
        connection => undefined}}.

terminate(_, _State) ->
    ok.

handle_call(_, _, #{connection := undefined}) ->
    ?LOG_ERROR("auth_hub_pg: no connect to db", []),
    {error, no_connect};
handle_call({insert, Statement, Args}, _From, State) ->
    #{connection := Conn} = State,
    Reply = sql_req_prepared(Conn, Statement, Args),
    {reply, Reply, State};
handle_call({select, Statement, Args}, _From, State) ->
    #{connection := Conn} = State,
    Reply = sql_req_prepared(Conn, Statement, Args),
    {reply, Reply, State};
handle_call({delete, Statement, Args}, _From, State) ->
    #{connection := Conn} = State,
    Reply = sql_req_prepared(Conn, Statement, Args),
    {reply, Reply, State};
handle_call({sql_req_not_prepared, Sql, Args}, _From, State) ->
    #{connection := Conn} = State,
    Resp = case epgsql:equery(Conn, Sql, Args) of
               {error, Reason} ->
                   ?LOG_ERROR("PostgreSQL sql_req_not_prepared error, ~p, ~p", [Sql, Reason]),
                   {error, Reason};
               RespOk -> RespOk
           end,
    {reply, Resp, State};
handle_call(Other, _From, State) ->
    ?LOG_ERROR("Invalid call to gen_server(auth_hub_pg) ~p", [Other]),
    {reply, <<"Invalid req">>, State}.

handle_cast(_Data, State) ->
    {noreply, State}.

handle_info(connect, State) -> % initialization
    #{connect_arg := Arg, timer_connect := TConn} = State,
    _ = erlang:cancel_timer(TConn),
    State1 = case epgsql:connect(Arg) of
                 {ok, Pid} ->
                     ok = parse(Pid),
                     State#{connection := Pid};
                 {error, _Error} ->
                     % ?LOG_ERROR("db connect error ~p", [Error]),
                     %  ok = timer:sleep(1000),
                     TConn1 = erlang:send_after(500, self(), connect),
                     State#{connection := undefined, timer_connect := TConn1}
             end,
    {noreply, State1};
handle_info(_Data, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


% ====================================================
% Help-functions for inverse functions
% ====================================================

-spec parse(pid()) -> ok.
parse(Conn) ->
    ?LOG_INFO("Parse OK", []),
    % {ok, _} = epgsql:parse(Conn, "delete_allow_role_in_roles", "DELETE FROM roles WHERE role = $1", [varchar]),
    % {ok, _} = epgsql:parse(Conn, "get_allow_roles", "SELECT role FROM allow_roles", []),
    % {ok, _} = epgsql:parse(Conn, "add_allow_role", "INSERT INTO allow_roles (role) VALUES ($1)", [varchar]),
    % {ok, _} = epgsql:parse(Conn, "delete_allow_role", "DELETE FROM allow_roles WHERE role = $1", [varchar]),
    % {ok, _} = epgsql:parse(Conn, "user_add", "INSERT INTO users (id, name, passhash) VALUES ($1, $2, $3)", [varchar, varchar, json]),
    % {ok, _} = epgsql:parse(Conn, "get_passhash", "SELECT passhash FROM users WHERE name = $1", [varchar]),
    % {ok, _} = epgsql:parse(Conn, "get_admin_passhash", "SELECT passhash FROM admins WHERE login = $1", [varchar]),
    % {ok, _} = epgsql:parse(Conn, "roles_add_by_name", "INSERT INTO roles (user_id, role) VALUES ((SELECT id FROM users WHERE name = $1), $2)", [varchar, varchar]),
    % {ok, _} = epgsql:parse(Conn, "get_all_users", "SELECT name, passhash FROM users", []),
    % {ok, _} = epgsql:parse(Conn, "get_roles_by_name", "SELECT role FROM roles WHERE user_id = (SELECT id FROM users WHERE name = $1)", [varchar]),
    % {ok, _} = epgsql:parse(Conn, "users_delete_by_name", "DELETE FROM users WHERE name = $1", [varchar]),
    % {ok, _} = epgsql:parse(Conn, "roles_delete_by_name", "DELETE FROM roles WHERE user_id = (SELECT id FROM users WHERE name = $1) AND role = $2", [varchar, varchar]),

    {ok, _} = epgsql:parse(Conn, "get_passhash", "SELECT passhash FROM users WHERE login=$1", [varchar]),
    {ok, _} = epgsql:parse(Conn, "insert_sid", "INSERT INTO sids (login, sid, ts_end) VALUES ($1, $2, $3)", [varchar, varchar, timestamp]),
    {ok, _} = epgsql:parse(Conn, "get_roles", "SELECT subsystem, role FROM roles WHERE login=$1", [varchar]),
    {ok, _} = epgsql:parse(Conn, "update_sid", "UPDATE sids SET sid=$2, ts_end=$3 WHERE login=$1", [varchar, varchar, timestamp]),

    {ok, _} = epgsql:parse(Conn, "download_sids", "SELECT sid, login, null, ts_end FROM sids", []),
    ok.

-spec sql_req_prepared(pid(), list(), list()) -> {error, term()} | {ok, Colon::list(), Val::list()} | {ok, integer()}.
sql_req_prepared(Conn, Statement, Args) ->
    case epgsql:prepared_query(Conn, Statement, Args) of
        {error, Error} ->
            ?LOG_ERROR("PostgreSQL prepared_query error(~p): ~p~n", [Statement, Error]),
            {error, Error};
        Other -> Other
    end.
