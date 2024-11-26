-module(auth_hub_req_api).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').

-export([init/2]).

-include("auth_hub.hrl").

-spec init(tuple(), list()) -> term().
init(Req, Opts) ->
    {HttpCode, RespMap} = handle_http_method(Req, Opts),
    RespBody = jsone:encode(RespMap),
    Resp = cowboy_req:reply(HttpCode, #{<<"content-type">> => <<"application/json; charset=UTF-8">>}, RespBody, Req),
    {ok, Resp, Opts}.

-spec handle_http_method(tuple(), list()) -> {integer(), map()}.
handle_http_method(Req, Opts) ->
    case {cowboy_req:method(Req), Opts} of
        {<<"GET">>, [Url]} when (Url == <<"/users/info">>) or (Url == <<"/allow/subsystems/roles/info">>) ->
            {HttpCode, RespMap} = handle_sid(Url, Req),
            ?LOG_DEBUG("Get reply ~p", [HttpCode]),
            {HttpCode, RespMap};
        {<<"POST">>, [Url]} when (Url =/= <<"/users/info">>) or (Url =/= <<"/allow/subsystems/roles/info">>) ->
            {HttpCode, RespMap} = handle_sid(Url, Req),
            ?LOG_DEBUG("Post reply ~p", [HttpCode]),
            {HttpCode, RespMap};
        {Method, _} ->
            ?LOG_ERROR("Method ~p not allowed ~p~n", [Method, Req]),
            {405, ?RESP_FAIL(<<"method not allowed">>)}
    end.

-spec handle_sid(atom(), tuple()) -> {integer(), map()}.
handle_sid(Url, Req) ->
    Sid = cowboy_req:header(<<"sid">>, Req, undefined),
    case auth_hub_tools:check_sid(Sid) of
        {Sid, Login, null, TsEnd} ->
            case auth_hub_pg:get_roles(Login) of
                null ->
                    {502, ?RESP_FAIL(<<"invalid db resp">>)};
                RolesMap ->
                    true = ets:insert(sids_cache, {Sid, Login, RolesMap, TsEnd}),
                    handle_body(Url, RolesMap, Req)
            end;
        {Sid, _Login, RolesMap, _TsEnd} ->
            handle_body(Url, RolesMap, Req);
        _Error ->
            ?LOG_ERROR("sid is invalid or legacy", []),
            {403, ?RESP_FAIL(<<"sid is invalid or legacy">>)}
    end.

-spec handle_body(binary(), map(), tuple()) -> {integer(), map()}.
handle_body(<<"/users/info">>, RolesMap, _Req) ->
    handle_auth(<<>>, <<"/users/info">>, RolesMap, #{});
handle_body(<<"/allow/subsystems/roles/info">> = Url, RolesMap, _Req) ->
    handle_auth(<<>>, Url, RolesMap, #{});
handle_body(Url, RolesMap, Req) ->
    case cowboy_req:has_body(Req) of
        true ->
            {ok, Body, _Req} = cowboy_req:read_body(Req),
            case jsone:try_decode(Body) of
                {error, Reason} ->
                    ?LOG_ERROR("Decode error, ~p", [Reason]),
                    {400, ?RESP_FAIL(<<"invalid request format">>)};
                {ok, #{<<"method">> := Method} = BodyMap, _} ->
                    handle_auth(Method, Url, RolesMap, BodyMap);
                {ok, OtherMap, _} ->
                    ?LOG_ERROR("Absent needed params ~p", [OtherMap]),
                    {422, ?RESP_FAIL(<<"absent needed params">>)}
            end;
        false ->
            ?LOG_ERROR("Missing body ~p~n", [Req]),
            {400, ?RESP_FAIL(<<"missing body">>)}
    end.

-spec handle_auth(binary(), binary(), map(), map()) -> {integer(), map()}.
handle_auth(Method, Url, RolesMap, BodyMap) ->
    Roles = maps:get(?SERVICE_SUBSYSTEM, RolesMap, []),
    case maps:get({Method, Url}, ?API_PERMIT_ROLES, undefined) of
        undefined ->
            ?LOG_ERROR("Invalid method", []),
            {422, ?RESP_FAIL(<<"invalid method">>)};
        PermitRoles ->
            case auth_hub_tools:check_roles(Roles, PermitRoles) of
                false ->
                    ?LOG_ERROR("Absent roles ~p in ~p", [PermitRoles, Roles]),
                    {401, ?RESP_FAIL(<<"absent role">>)};
                true ->
                    handle_method(Method, Url, BodyMap)
            end
    end.

-spec handle_method(binary(), binary(), map()) -> {integer(), binary()}.
handle_method(<<"create_users">>, <<"/users">>, #{<<"users">> := ListMap}) when is_list(ListMap) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {429, ?RESP_FAIL(<<"too many requests">>)};
        WorkerPid ->
            Reply = create_users(ListMap, WorkerPid),
            ok = poolboy:checkin(pg_pool, WorkerPid),
            {200, #{<<"results">> => Reply}}
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("No workers in pg_pool ~p", [Reason]),
            {429, ?RESP_FAIL(<<"too many requests">>)}
    end;
handle_method(<<"delete_users">>, <<"/users">>, #{<<"logins">> := ListMap}) when is_list(ListMap) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {429, ?RESP_FAIL(<<"too many requests">>)};
        WorkerPid ->
            Reply = delete_users(ListMap, WorkerPid),
            ok = poolboy:checkin(pg_pool, WorkerPid),
            {200, #{<<"results">> => Reply}}
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("No workers in pg_pool ~p", [Reason]),
            {429, ?RESP_FAIL(<<"too many requests">>)}
    end;
handle_method(<<>>, <<"/users/info">>, #{}) ->
    case auth_hub_pg:select("get_users_all_info", []) of
        {error, Reason} ->
            ?LOG_ERROR("Invalid db response, ~p", [Reason]),
            {502, ?RESP_FAIL(<<"invalid db response">>)};
        {ok, _Colons, DbResp} ->
            UsersMap = parse_users_info(DbResp, #{}),

            Logins = maps:keys(UsersMap),
            ListResp = construct_response(Logins, UsersMap),
            {200, ?RESP_SUCCESS(ListResp)}
    end;
handle_method(Method, <<"/roles/change">>, BodyMap) ->
    auth_hub_api_allow:change_roles(Method, BodyMap);
handle_method(<<>>, <<"/allow/subsystems/roles/info">>, #{}) ->
    auth_hub_api_allow:get_allow_roles();
handle_method(<<"create_roles">>, <<"/allow/roles/change">>, BodyMap) ->
    auth_hub_api_allow:create_roles(BodyMap);
handle_method(<<"delete_roles">>, <<"/allow/roles/change">>, BodyMap) ->
    auth_hub_api_allow:delete_roles(BodyMap);
handle_method(<<"create_subsystems">>, <<"/allow/subsystems/change">>, BodyMap) ->
    auth_hub_api_allow:create_subsystems(BodyMap);
handle_method(<<"delete_subsystems">>, <<"/allow/subsystems/change">>, BodyMap) ->
    auth_hub_api_allow:delete_subsystems(BodyMap);
handle_method(Method, Url, OtherBody) ->
    ?LOG_ERROR("Invalid request format ~p, ~p, ~p", [Method, Url, OtherBody]),
    {422, ?RESP_FAIL(<<"invalid request format">>)}.


%% ========= get_all_users_info ====== /users/info =========

-spec parse_users_info(DbResp :: list(), map()) -> map().
parse_users_info([], Result) -> Result;
parse_users_info([{Login, null, null} | T], Result) ->
    ListTab = ets:tab2list(subsys_cache),
    SubSystems = add_subsyses(ListTab, #{}),
    Result1 = Result#{Login => SubSystems},
    parse_users_info(T, Result1);
parse_users_info([{Login, SubSys, Role} | T], Result) ->
    Result1 = case maps:get(Login, Result, null) of
                  null ->
                      ListTab = ets:tab2list(subsys_cache),
                      SubSystems = add_subsyses(ListTab, #{}),
                      Result#{Login => SubSystems#{SubSys => [Role]}};
                  #{SubSys := Roles} = SubSyses ->
                      Result#{Login := SubSyses#{SubSys := [Role | Roles]}}
              end,
    parse_users_info(T, Result1).

-spec add_subsyses(list(), map()) -> map().
add_subsyses([], Result) -> Result;
add_subsyses([{SubSys} | T], Result) ->
    Result1 = Result#{SubSys => []},
    add_subsyses(T, Result1).

-spec construct_response(list(), map()) -> list().
construct_response([], _UsersMap) -> [];
construct_response([Login | T], UsersMap) ->
    #{Login := SubSystems} = UsersMap,
    SidList = ets:select(sids_cache, [{
        {'$1', '$2', '_', '_'},
        [{'=:=', '$2', Login}],
        ['$1']
    }]),
    ActiveSid = case SidList of
                    [] -> false;
                    [_Sid] -> true
                end,
    MapResp = #{<<"login">> => Login, <<"subsystem_roles">> => SubSystems, <<"has_activ_sid">> => ActiveSid},
    [MapResp | construct_response(T, UsersMap)].


%% ========= create_users ====== /users =========

-spec create_users(list(), pid()) -> list().
create_users([], _PgPid) -> [];
create_users([#{<<"login">> := Login, <<"pass">> := Pass} | T], PgPid) ->
    case auth_hub_tools:validation(create_users, {Login, Pass}) of
        true ->
            [{salt, Salt}] = ets:lookup(opts, salt),
            SaltBin = list_to_binary(Salt),
            PassHash = io_lib:format("~64.16.0b", [binary:decode_unsigned(crypto:hash(sha256, <<Pass/binary, SaltBin/binary>>))]),
            case auth_hub_pg:insert(PgPid, "create_user", [Login, PassHash]) of
                {error, {_, _, _, unique_violation, _, [{constraint_name, <<"unique_pass">>} | _]} = Reason} ->
                    ?LOG_ERROR("create_users incorrect pass ~p", [Reason]),
                    [?RESP_FAIL_USERS(Login, <<"this pass is using now">>) | create_users(T, PgPid)];
                {error, {_, _, _, unique_violation, _, [{constraint_name, <<"login_pk">>} | _]} = Reason} ->
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
create_users([_OtherMap | T], PgPid) -> create_users(T, PgPid).


%% ========= delete_users ====== /users =========

-spec delete_users(list(), pid()) -> list().
delete_users([], _PgPid) -> [];
delete_users([<<"admin">> | T], PgPid) ->
    [?RESP_FAIL_USERS(<<"admin">>, <<"root user">>) | delete_users(T, PgPid)];
delete_users([Login | T], PgPid) ->
    case auth_hub_tools:valid_login(Login) of
        false ->
            ?LOG_ERROR("delete_users invalid params, login ~p", [Login]),
            [?RESP_FAIL_USERS(Login, <<"invalid login">>) | delete_users(T, PgPid)];
        true ->
            case auth_hub_pg:delete(PgPid, "delete_user", [Login]) of
                {error, Reason} ->
                    ?LOG_ERROR("delete_users db error ~p", [Reason]),
                    [?RESP_FAIL_USERS(Login, <<"invalid db response">>) | delete_users(T, PgPid)];
                {ok, _Column, [{<<"ok">>}]} ->
                    ok = ets_delete_sid(Login),
                    [#{<<"login">> => Login, <<"success">> => true} | delete_users(T, PgPid)]
            end
    end.

-spec ets_delete_sid(binary()) -> ok.
ets_delete_sid(Login) ->
    SidList = ets:select(sids_cache, [{
        {'$1', '$2', '_', '_'},
        [{'=:=', '$2', Login}],
        ['$1']
    }]),
    case SidList of
        [Sid] ->
            true = ets:delete(sids_cache, Sid);
        [] ->
            ok
    end,
    ok.
