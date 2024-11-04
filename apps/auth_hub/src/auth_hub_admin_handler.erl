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
    {ok, Body, _Req} = cowboy_req:read_body(Req),
    Sid = cowboy_req:header(<<"sid">>, Req, undefined),
    ?LOG_DEBUG("Post request ~p", [Body]),
    {HttpCode, RespMap} = handle_req(Body, Sid),
    ?LOG_DEBUG("Post reply ~p", [HttpCode]),
    RespBody = jsone:encode(RespMap),
    cowboy_req:reply(HttpCode, #{<<"content-type">> => <<"application/json; charset=UTF-8">>}, RespBody, Req);
handle_post(<<"POST">>, false, Req) ->
    ?LOG_ERROR("Missing body ~p~n", [Req]),
    cowboy_req:reply(400, #{}, <<"Missing body.">>, Req);
handle_post(Method, _, Req) ->
    ?LOG_ERROR("Method ~p not allowed ~p~n", [Method, Req]),
    cowboy_req:reply(405, Req).

-spec handle_req(binary(), binary()|undefined) -> {integer(), map()}.
handle_req(Body, Sid) ->
    case auth_hub_helper:check_sid(Sid) of
        {Sid, Login, null, TsEnd} ->
            case auth_hub_pg:get_roles(Login) of
                null ->
                    {502, ?RESP_FAIL(<<"invalid db resp">>)};
                RolesMap ->
                    true = ets:insert(sids_cache, {Sid, Login, RolesMap, TsEnd}),
                    handle_body(Body, RolesMap)
            end;
        {Sid, _Login, RolesMap, _TsEnd} ->
            handle_body(Body, RolesMap);
        _Error ->
            ?LOG_ERROR("sid is invalid or legacy", []),
            {403, ?RESP_FAIL(<<"sid is invalid or legacy">>)}
    end.

-spec handle_body(binary(), map()) -> {integer(), map()}.
handle_body(Body, RolesTab) ->
    case jsone:try_decode(Body) of
        {error, Reason} ->
            ?LOG_ERROR("Decode error, ~p", [Reason]),
            {400, ?JSON_ERROR(<<"invalid request format">>)};
        {ok, #{<<"method">> := Method} = BodyMap, _} ->
            Roles = maps:get(?SERVICE_SUBSYSTEM, RolesTab, []),
            case maps:get(Method, ?SERVICE_ROLES, undefined) of
                undefined ->
                    ?LOG_ERROR("Invalid method", []),
                    {422, ?RESP_FAIL(<<"invalid method">>)};
                PermitRoles ->
                    case auth_hub_helper:check_roles(Roles, PermitRoles) of
                        false ->
                            ?LOG_ERROR("Absent roles ~p in ~p", [PermitRoles, Roles]),
                            {401, ?RESP_FAIL(<<"absent role">>)};
                        true ->
                            handle_method(BodyMap)
                    end
            end;
        _OtherMap ->
            ?LOG_ERROR("Absent needed params", []),
            {422, ?JSON_ERROR(<<"absent needed params">>)}
    end.

handle_method(_BodyMap) ->
    {200, ?RESP_SUCCESS(<<"ok">>)}.

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
