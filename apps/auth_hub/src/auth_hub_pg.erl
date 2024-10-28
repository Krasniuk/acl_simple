-module(auth_hub_pg).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').
-behavior(gen_server).

-include("auth_hub.hrl").

-export([start_link/1]). % Export for poolboy
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]). % Export for gen_server
-export([select/2, insert/2, delete/2]).

% ====================================================
% Clients functions
% ====================================================

start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

select(Statement, Args) ->
    case poolboy:checkout(pg_pool) of
        full ->
            ?LOG_ERROR("All workers are busy. Pool(~p)", [pg_pool]),
            {error, full_pool};
        WorkerPid ->
            Reply = gen_server:call(WorkerPid, {select, Statement, Args}),
            ok = poolboy:checkin(pg_pool, WorkerPid),
            Reply
    end.

insert(Statement, Args) ->
    case poolboy:checkout(pg_pool) of
        full ->
            ?LOG_ERROR("All workers are busy. Pool(~p)", [pg_pool]),
            {error, full_pool};
        WorkerPid ->
            Reply = gen_server:call(WorkerPid, {insert, Statement, Args}),
            ok = poolboy:checkin(pg_pool, WorkerPid),
            Reply
    end.

delete(Statement, Args) ->
    case poolboy:checkout(pg_pool) of
        full ->
            ?LOG_ERROR("All workers are busy. Pool(~p)", [pg_pool]),
            {error, full_pool};
        WorkerPid ->
            Reply = gen_server:call(WorkerPid, {delete, Statement, Args}),
            ok = poolboy:checkin(pg_pool, WorkerPid),
            Reply
    end.


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

handle_call({insert, Statement, Args}, _From, State) ->
    #{connection := Conn} = State,
    Reply = send_to_bd(Conn, Statement, Args),
    {reply, Reply, State};
handle_call({select, Statement, Args}, _From, State) ->
    #{connection := Conn} = State,
    Reply = send_to_bd(Conn, Statement, Args),
    {reply, Reply, State};
handle_call({delete, Statement, Args}, _From, State) ->
    #{connection := Conn} = State,
    Reply = send_to_bd(Conn, Statement, Args),
    {reply, Reply, State}.

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
    ok.

send_to_bd(undefined, _, _) ->
    ?LOG_ERROR("auth_hub_pg: no connect to db", []),
    {error, no_connect};
send_to_bd(Conn, Statement, Args) -> % INTERFACE between prepared_query of DB, and handle_call...
    case epgsql:prepared_query(Conn, Statement, Args) of
        {error, Error} ->
            ?LOG_ERROR("PostgreSQL prepared_query error(~p): ~p~n", [Statement, Error]),
            {error, Error};
        Other -> Other
    end.
