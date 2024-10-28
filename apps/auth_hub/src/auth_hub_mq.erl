-module(auth_hub_mq).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').

-behaviour(gen_server).

-include("auth_hub.hrl").
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
    {ok, RawQueue} = application:get_env(rims, mq_queue),
    {ok, Limit} = application:get_env(rims, mq_consume_limit),
    Queue = list_to_binary(RawQueue),
    TimerConn = erlang:send_after(3000, Pid, {connect, Queue}),
    TimerConsume = erlang:send_after(3200, Pid, {consume, Limit}),
    {ok, #{timer_conn => TimerConn, pid_consumer => Pid, timer_consume => TimerConsume}}.

handle_call(Request, _From, State) ->
    ?LOG_ERROR("Unknown call msg in rims worker ~p~n", [Request]),
    {reply, ok, State}.

handle_cast(Msg, State) ->
    ?LOG_ERROR("Unknown cast msg in rims worker ~p~n", [Msg]),
    {noreply, State}.

handle_info({connect, Queue}, #{timer_conn := OldTimer, pid_consumer := Pid} = State) ->
    _ = erlang:cancel_timer(OldTimer),
    {ok, Host} = application:get_env(rims, mq_host),
    {ok, ReserveHost} = application:get_env(rims, mq_reserve_host),
    {ok, VHostRaw} = application:get_env(rims, mq_virtual_host),
    {ok, UserRaw} = application:get_env(rims, mq_user),
    {ok, PassRaw} = application:get_env(rims, mq_password),
    VHost = list_to_binary(VHostRaw),
    User = list_to_binary(UserRaw),
    Pass = list_to_binary(PassRaw),
    {Connection, Channel, ConnMonitorRef,
        ChMonitorRef, NewQueue, Timer} = connect(Queue, [Host, ReserveHost], VHost, User, Pass, Pid),
    {noreply, State#{connection => Connection, channel => Channel,
        conn_monitor => ConnMonitorRef, ch_monitor => ChMonitorRef,
        queue => NewQueue, timer_conn => Timer}};
handle_info({consume, Limit}, State) ->
    #{pid_consumer := Pid, timer_consume := OldTimer,
        queue := Queue, channel := Channel
    } = State,
    _ = erlang:cancel_timer(OldTimer),
    Interval = case Queue =:= no_queue of
                   true ->
                       ?LOG_ERROR("Error consume, no_queue~n", []),
                       60000;
                   false ->
                       ok = consume_handler(Channel, Limit, Queue),
                       3000
               end,
    Timer = erlang:send_after(Interval, Pid, {consume, Limit}),
    {noreply, State#{timer_consume => Timer}};
handle_info({'DOWN', RefMonitor, process, _ClientPid, Info}, State) ->
    #{consumer_pid := Pid, conn_monitor := ConnMonitor,
        ch_monitor := ChMonitor, queue := Queue
    } = State,
    true = erlang:demonitor(ConnMonitor),
    true = erlang:demonitor(ChMonitor),
    true = ets:delete(opts, {mq_consumer_pid, Queue}),
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
    ?LOG_CRITICAL("Terminate rims mq_manager with reason ~p~n", [Reason]),
    case Queue of
        no_queue ->
            ok;
        _ ->
            true = ets:delete(opts, {mq_consumer_pid, binary_to_atom(Queue, utf8)})
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
            true = ets:insert(opts, {{mq_consumer_pid, Queue, Pid}}),
            {Connection, Channel, ConnMonitor, ChMonitor, Queue, null};
        {error, Reason} ->
            ?LOG_ERROR("Can't connection consumer to RabbitMQ host ~p by reason ~p~n", [Host, Reason]),
            connect(Queue, ReserveHosts, VHost, User, Pass, Pid)
    end.

consume_handler(undefined, _Limit, _Queue) ->
    ?LOG_ERROR("MQ channel is undefined, get queue unavailable~n", []);
consume_handler(_Channel, 0, _Queue) ->
    ok;
consume_handler(_Channel, Limit, Queue) when Limit < 0 ->
    ?LOG_ERROR("Queue limit ~p has negative value ~p~n", [Queue, Limit]);
consume_handler(Channel, Limit, Queue) ->
    Get = #'basic.get'{queue = Queue},
    case amqp_channel:call(Channel, Get) of
        {'basic.get_empty', <<>>} ->
            ok;
        {#'basic.get_ok'{delivery_tag = Tag}, Content} ->
            {amqp_msg, _, MsgRaw} = Content,
            ?LOG_INFO("Resp_RabbitMQ = ~p", [MsgRaw]),
            consume_handler(Channel, Limit-1, Queue)
    end.

%%% =============================================================
