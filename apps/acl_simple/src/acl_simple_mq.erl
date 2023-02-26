-module(acl_simple_mq).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').

-behaviour(gen_server).

-include("acl_simple.hrl").
-include_lib("amqp_client/include/amqp_client.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/0]).


%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
    terminate/2, code_change/3]).


%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link() ->
    gen_server:start_link(?MODULE, [], []).


%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([]) ->
    Pid = self(),
    {ok, RawQueue} = application:get_env(acl_simple, mq_queue),
    Queue = list_to_binary(RawQueue),
    TimerConn = erlang:send_after(3000, Pid, {connect, Queue}),
    {ok, #{timer_conn => TimerConn, pid_consumer => Pid}}.

handle_call(Request, _From, State) ->
    ?LOG_ERROR("Unknown call msg in acl_simple worker ~p~n", [Request]),
    {reply, ok, State}.

handle_cast(Msg, State) ->
    ?LOG_ERROR("Unknown cast msg in acl_simple worker ~p~n", [Msg]),
    {noreply, State}.

handle_info({connect, Queue}, #{timer_conn := OldTimer, pid_consumer := Pid} = State) ->
    _ = erlang:cancel_timer(OldTimer),
    {ok, Host} = application:get_env(acl_simple, mq_host),
    {ok, ReserveHost} = application:get_env(acl_simple, mq_reserve_host),
    {ok, VHostRaw} = application:get_env(acl_simple, mq_virtual_host),
    {ok, UserRaw} = application:get_env(acl_simple, mq_user),
    {ok, PassRaw} = application:get_env(acl_simple, mq_password),
    VHost = list_to_binary(VHostRaw),
    User = list_to_binary(UserRaw),
    Pass = list_to_binary(PassRaw),
    {Connection, Channel, ConnMonitorRef,
        ChMonitorRef, NewQueue, Timer} = connect(Queue, [Host, ReserveHost], VHost, User, Pass, Pid),
    {noreply, State#{connection => Connection, channel => Channel,
        conn_monitor => ConnMonitorRef, ch_monitor => ChMonitorRef,
        queue => NewQueue, timer_conn => Timer}};

handle_info({'DOWN', RefMonitor, process, _ClientPid, Info}, State) ->
    #{consumer_pid := Pid, conn_monitor := ConnMonitor,
        ch_monitor := ChMonitor, queue := Queue
    } = State,
    true = erlang:demonitor(ConnMonitor),
    true = erlang:demonitor(ChMonitor),
    true = ets:delete(acl_simple, {mq_consumer_pid, Queue}),
    case RefMonitor of
        ConnMonitor ->
            ?LOG_ERROR("Connection consumer to RabbitMQ is down by reason ~p~n", [Info]);
        ChMonitor ->
            #{connection := Connection} = State,
            _ = amqp_connection:close(Connection),
            ?LOG_ERROR("Channel consumer to RabbitMQ is down by reason ~p~n", [Info])
    end,
    Timer = erlang:send_after(5000, Pid, {connect, Queue}),
    {noreply, State#{connection => undefined, channel => undefined,
        conn_monitor => undefined, ch_monitor => undefined,
        queue => no_queue, timer_conn => Timer}};
handle_info(Info, State) ->
    #{channel := Channel, connection := Connection,
        queue := Queue, consumer_pid := Pid
    } = State,
    ok = amqp_channel:close(Channel),
    ok = amqp_connection:close(Connection),
    Timer = erlang:send_after(3000, Pid, {connect, Queue}),
    ?LOG_ERROR("Unknown info message in consumer reconnect channel ~p~n", [Info]),
    {noreply, State#{connection => undefined, channel => undefined,
        conn_monitor => undefined, ch_monitor => undefined,
        queue => no_queue, timer_conn => Timer}}.

terminate(Reason, #{channel := Channel, connection := Connection, queue := Queue}) ->
    ?LOG_CRITICAL("Terminate acl_simple mq_manager with reason ~p~n", [Reason]),
    case Queue of
        no_queue ->
            ok;
        _ ->
            true = ets:delete(acl_simple, {mq_consumer_pid, binary_to_atom(Queue, utf8)})
    end,
    ok = amqp_channel:close(Channel),
    ok = amqp_connection:close(Connection).

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec connect(term(), list(), list(), list(), list(), pid()) -> tuple().
connect(Queue, [], _VHost, _User, _Pass, Pid) ->
    ?LOG_ERROR("Can't connection to RabbitMQ at all, reconnect after 5 sec~n", []),
    Timer = erlang:send_after(5000, Pid, {connect, Queue}),
    {undefined, undefined, undefined, undefined, no_queue, Timer};
connect(Queue, [Host|ReserveHosts], VHost, User, Pass, Pid) ->
    case amqp_connection:start(#amqp_params_network{username = User, password = Pass, virtual_host = VHost, host = Host}) of
        {ok, Connection} ->
            {ok, Channel} = amqp_connection:open_channel(Connection),
            ConnMonitor = erlang:monitor(process, Connection),
            ChMonitor = erlang:monitor(process, Channel),
            ?LOG_DEBUG("Succesful connect to RubbitMQ.", []),
            true = ets:insert(acl_simple, {{mq_consumer_pid, Queue, Pid}}),
            {Connection, Channel, ConnMonitor, ChMonitor, Queue, null};
        {error, Reason} ->
            ?LOG_ERROR("Can't connection consumer to RabbitMQ host ~p by reason ~p~n", [Host, Reason]),
            connect(Queue, ReserveHosts, VHost, User, Pass, Pid)
    end.