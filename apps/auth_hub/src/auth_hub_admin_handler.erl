-module(auth_hub_admin_handler).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').

-export([init/2]).

-include("auth_hub.hrl").

init(Req, Opts) ->
    Method = cowboy_req:method(Req),
    HasBody = cowboy_req:has_body(Req),
    Resp = handle_post(Method, HasBody, Req),
    {ok, Resp, Opts}.

handle_post(<<"POST">>, true, Req) ->
    handle_req(Req);
handle_post(<<"POST">>, false, Req) ->
    ?LOG_ERROR("Missing body ~p~n", [Req]),
    cowboy_req:reply(400, #{}, <<"Missing body.">>, Req);
handle_post(Method, _, Req) ->
    ?LOG_ERROR("Method ~p not allowed ~p~n", [Method, Req]),
    cowboy_req:reply(405, Req).

handle_req(Req) ->
    {ok, Body, _Req} = cowboy_req:read_body(Req),
    ?LOG_DEBUG("Post request ~p", [Body]),
    {Status, Json} = handle_body(Body),
    ?LOG_DEBUG("Post reply ~p~n----- ----- -----~n", [Json]),
    cowboy_req:reply(Status, #{<<"content-type">> => <<"application/json; charset=UTF-8">>}, Json, Req).

handle_body(Body) ->
    try jsone:decode(Body) of
        Map ->
            handle_package(Map)
    catch
        Exception:Reason ->
            ?LOG_ERROR("jsone:decode error (~p : ~p)", [Exception, Reason]),
            {400, jsone:encode(?JSON_ERROR(<<"Invalid request format">>))}
    end.

handle_package(Map) ->
    try
        #{<<"auth">> := AuthPack} = Map,
        #{<<"login">> := Login, <<"passhash">> := PassHash} = AuthPack,
        #{<<"parameters">> := ParamPack} = Map,
        handle_parameters({Login, PassHash}, ParamPack)
    catch
        Class:Reason ->
            ?LOG_ERROR("Catch error (~p : ~p)", [Class, Reason]),
            {206, jsone:encode(?JSON_ERROR(<<"Invalid request format">>))}
    end.

handle_parameters({Login, PassHash}, #{<<"method">> := Method} = ParamPack) ->
    case auth(Login, PassHash, Method) of
        true ->
            handle_method(Method, ParamPack);
        false ->
            ?LOG_ERROR("Auth error, login ~p method ~p~n", [Login, Method]),
            {401, jsone:encode(?JSON_ERROR(<<"Invalid passhash or role absent">>))}
    end.

-spec auth(binary(), list(), binary()) -> true|false.
auth(Login, Hash, _Method) ->
    {ok, _, [{RealHash}]} = auth_hub_pg:select("get_admin_passhash", [Login]),
    RealHash == Hash.

-spec handle_method(binary(), map()) -> {integer(), binary()}.
handle_method(<<"user_add">>, Map) ->
    [{_, Pid}] = ets:lookup(auth_hub, auth_hub_server),
    #{<<"user">> := NewUser, <<"passhash">> := PassHash} = Map,
    Reply = gen_server:call(Pid, {user_add, NewUser, PassHash}),
    {200, jsone:encode(Reply)};
handle_method(<<"user_delete">>, Map) ->
    [{_, Pid}] = ets:lookup(auth_hub, auth_hub_server),
    User = maps:get(<<"user">>, Map),
    Reply = gen_server:call(Pid, {user_delete, User}),
    {200, jsone:encode(Reply)};
handle_method(<<"show_all_users">>, _Map) ->
    [{_, Pid}] = ets:lookup(auth_hub, auth_hub_server),
    Reply = gen_server:call(Pid, {show_all_users}),
    {200, jsone:encode(Reply)};
% --- roles ---
handle_method(<<"roles_add">>, Map) ->
    [{_, Pid}] = ets:lookup(auth_hub, auth_hub_server),
    User = maps:get(<<"user">>, Map),
    Roles = maps:get(<<"roles">>, Map),
    Reply = gen_server:call(Pid, {roles_add, User, Roles}),
    {200, jsone:encode(Reply)};
handle_method(<<"roles_delete">>, Map) ->
    [{_, Pid}] = ets:lookup(auth_hub, auth_hub_server),
    User = maps:get(<<"user">>, Map),
    Roles = maps:get(<<"roles">>, Map),
    Reply = gen_server:call(Pid, {roles_delete, User, Roles}),
    {200, jsone:encode(Reply)};
handle_method(<<"show_roles">>, Map) ->
    [{_, Pid}] = ets:lookup(auth_hub, auth_hub_server),
    User = maps:get(<<"user">>, Map),
    Reply = gen_server:call(Pid, {show_roles, User}),
    {200, jsone:encode(Reply)};
% --- allow_roles ---
handle_method(<<"show_allow_roles">>, _Map) ->
    [{_, Pid}] = ets:lookup(auth_hub, auth_hub_server),
    Reply = gen_server:call(Pid, {show_allow_roles}),
    {200, jsone:encode(Reply)};
handle_method(<<"add_allow_roles">>, Map) ->
    [{_, Pid}] = ets:lookup(auth_hub, auth_hub_server),
    #{<<"roles">> := ListRoles} = Map,
    Reply = gen_server:call(Pid, {add_allow_roles, ListRoles}),
    {200, jsone:encode(Reply)};
handle_method(<<"delete_allow_roles">>, Map) ->
    [{_, Pid}] = ets:lookup(auth_hub, auth_hub_server),
    #{<<"roles">> := ListRoles} = Map,
    Reply = gen_server:call(Pid, {delete_allow_roles, ListRoles}),
    {200, jsone:encode(Reply)}.
