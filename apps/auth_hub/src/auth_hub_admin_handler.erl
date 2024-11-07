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
                            handle_method(Method, BodyMap)
                    end
            end;
        {ok, OtherMap, _} ->
            ?LOG_ERROR("Absent needed params ~p", [OtherMap]),
            {422, ?JSON_ERROR(<<"absent needed params">>)}
    end.

-spec handle_method(binary(), map()) -> {integer(), binary()}.
handle_method(<<"create_users">>, #{<<"users">> := ListMap}) when is_list(ListMap) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {429, ?RESP_FAIL(<<"too many requests">>)};
        WorkerPid ->
            Reply = create_users(ListMap, WorkerPid),
            ok = poolboy:checkin(pg_pool, WorkerPid),
            {200, #{<<"users">> => Reply}}
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("No workers in pg_pool ~p", [Reason]),
            {429, ?RESP_FAIL(<<"too many requests">>)}
    end;
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
    {200, jsone:encode(Reply)};
handle_method(_Method, _OtherBody) ->
    ?LOG_ERROR("Incorrect body or method", []),
    {422, ?JSON_ERROR(<<"absent needed params">>)}.


-spec create_users(list(), pid()) -> list().
create_users([], _PgPid) -> [];
create_users([#{<<"login">> := Login, <<"pass">> := Pass}|T], PgPid) when is_binary(Login) and is_binary(Pass) ->
    ValidLogin = valid_login(Login),
    ValidPass = valid_pass(Pass),
    case not(lists:member(false, [ValidLogin, ValidPass])) of
        true ->
            [{salt, Salt}] = ets:lookup(opts, salt),
            SaltBin = list_to_binary(Salt),
            PassHash = io_lib:format("~64.16.0b", [binary:decode_unsigned(crypto:hash(sha256, <<Pass/binary, SaltBin/binary>>))]),
            case auth_hub_pg:insert(PgPid, "create_user", [Login, PassHash]) of
                {error, {_, _, _, unique_violation, _, [{constraint_name,<<"unique_pass">>}|_]} = Reason} ->
                    ?LOG_ERROR("create_users incorrect pass ~p", [Reason]),
                    [?RESP_FAIL_USERS(Login, <<"this pass is using now">>) | create_users(T, PgPid)];
                {error, {_, _, _, unique_violation, _, [{constraint_name,<<"login_pk">>}|_]} = Reason} ->
                    ?LOG_ERROR("create_users incorrect pass ~p", [Reason]),
                    [?RESP_FAIL_USERS(Login, <<"this login is using now">>) | create_users(T, PgPid)];
                {error, Reason} ->
                    ?LOG_ERROR("create_users db error ~p", [Reason]),
                    [?RESP_FAIL_USERS(Login, <<"invalid db response">>) | create_users(T, PgPid)];
                {ok, 1} ->
                    [#{<<"login">> => Login, <<"success">> => true} | create_users(T, PgPid)]
            end;
        false ->
            ?LOG_ERROR("create_users invalid params, login ~p", [Login]),
            [?RESP_FAIL_USERS(Login, <<"invalid params">>) | create_users(T, PgPid)]
    end;
create_users([_OtherMap|T], PgPid) -> create_users(T, PgPid).

-spec valid_login(binary()) -> boolean().
valid_login(Login) when (byte_size(Login) > 2) and (byte_size(Login) < 50) ->
    Len = byte_size(Login),
    {match, [{0, Len}]} =:= re:run(Login, "[a-zA-Z][a-zA-Z_\\d]*", []);
valid_login(_Login) -> false.

-spec valid_pass(binary()) -> boolean().
valid_pass(Pass) when (byte_size(Pass) >= 8) and (byte_size(Pass) < 100) ->
    Len = byte_size(Pass),
    {match, [{0, Len}]} =:= re:run(Pass, "[a-zA-Z_\\d-#&$%]*", []);
valid_pass(_Other) -> false.