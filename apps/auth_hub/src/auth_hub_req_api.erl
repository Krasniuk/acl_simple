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
handle_auth(Method, Url, #{<<"authHub">> := Spaces}, BodyMap) ->
    case maps:get({Method, Url}, ?API_PERMIT_ROLES, undefined) of
        undefined ->
            ?LOG_ERROR("Invalid method", []),
            {422, ?RESP_FAIL(<<"invalid method">>)};
        PermitRoles ->
            Keys = maps:keys(Spaces),
            case get_access_spaces(Keys, Spaces, PermitRoles) of
                [] ->
                    ?LOG_ERROR("Absent roles ~p in ~p", [PermitRoles, Spaces]),
                    {401, ?RESP_FAIL(<<"absent role">>)};
                SpacesAccess ->
                    handle_method(Method, Url, BodyMap, SpacesAccess)
            end
    end;
handle_auth(_, _, RolesMap, _) ->
    ?LOG_ERROR("Absent roles ~p", [RolesMap]),
    {401, ?RESP_FAIL(<<"absent role">>)}.

-spec get_access_spaces(list(), map(), list()) -> list().
get_access_spaces([], _SpacesMap, _PermitRoles) -> [];
get_access_spaces([Space | T], SpacesMap, PermitRoles) ->
    #{Space := Roles} = SpacesMap,
    case auth_hub_tools:check_roles(Roles, PermitRoles) of
        true ->
            [Space | get_access_spaces(T, SpacesMap, PermitRoles)];
        false ->
            get_access_spaces(T, SpacesMap, PermitRoles)
    end.


-spec handle_method(binary(), binary(), map(), list()) -> {integer(), binary()}.
handle_method(<<"create_users">>, <<"/users">>, #{<<"users">> := ListMap}, _) when is_list(ListMap) ->
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
handle_method(<<"delete_users">>, <<"/users">>, #{<<"logins">> := ListMap}, _) when is_list(ListMap) ->
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
handle_method(<<>>, <<"/users/info">>, #{}, SpacesAccess) ->
    case auth_hub_pg:select("get_users_all_info", []) of
        {error, Reason} ->
            ?LOG_ERROR("Invalid db response, ~p", [Reason]),
            {502, ?RESP_FAIL(<<"invalid db response">>)};
        {ok, _Colons, DbResp} ->
            UsersMap = parse_users_info(DbResp, SpacesAccess, #{}),
            Logins = maps:keys(UsersMap),
            ListResp = construct_response(Logins, UsersMap),
            {200, ?RESP_SUCCESS(ListResp)}
    end;
handle_method(<<"add_roles">>, <<"/roles/change">>, #{<<"changes">> := ListOperations}, SpacesAccess) when is_list(ListOperations) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {429, ?RESP_FAIL(<<"too many requests">>)};
        WorkerPid ->
            Reply = handler_add_roles(ListOperations, SpacesAccess),
            ok = poolboy:checkin(pg_pool, WorkerPid),
            {200, #{<<"results">> => Reply}}
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("No workers in pg_pool ~p", [Reason]),
            {429, ?RESP_FAIL(<<"too many requests">>)}
    end;
handle_method(<<"remove_roles">>, <<"/roles/change">>, #{<<"changes">> := ListOperations}, SpacesAccess) when is_list(ListOperations) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {429, ?RESP_FAIL(<<"too many requests">>)};
        WorkerPid ->
            Reply = remove_roles_handler(ListOperations, SpacesAccess),
            ok = poolboy:checkin(pg_pool, WorkerPid),
            {200, #{<<"results">> => Reply}}
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("No workers in pg_pool ~p", [Reason]),
            {429, ?RESP_FAIL(<<"too many requests">>)}
    end;
handle_method(<<>>, <<"/allow/subsystems/roles/info">>, #{}, SpacesAccess) ->
    auth_hub_api_allow:get_allow_roles(SpacesAccess);
handle_method(<<"create_roles">>, <<"/allow/roles/change">>, BodyMap, SpacesAccess) ->
    auth_hub_api_allow:create_roles(BodyMap, SpacesAccess);
handle_method(<<"delete_roles">>, <<"/allow/roles/change">>, BodyMap, SpacesAccess) ->
    auth_hub_api_allow:delete_roles(BodyMap, SpacesAccess);
handle_method(<<"create_subsystems">>, <<"/allow/subsystems/change">>, BodyMap, _) ->
    auth_hub_api_allow:create_subsystems(BodyMap);
handle_method(<<"delete_subsystems">>, <<"/allow/subsystems/change">>, BodyMap, _) ->
    auth_hub_api_allow:delete_subsystems(BodyMap);
handle_method(Method, Url, OtherBody, _) ->
    ?LOG_ERROR("Invalid request format ~p, ~p, ~p", [Method, Url, OtherBody]),
    {422, ?RESP_FAIL(<<"invalid request format">>)}.


%% ========= get_all_users_info ====== /users/info =========

-spec parse_users_info(DbResp :: list(), list(), map()) -> map().
parse_users_info([], _SpacesAccess, Result) -> Result;
parse_users_info([{Login, null, null, null} | T], SpacesAccess, Result) ->
    SubSystems = add_subsyses(SpacesAccess, #{}),
    case lists:member(<<"authHub">>, SpacesAccess) of
        false ->
            Result1 = Result#{Login => SubSystems},
            parse_users_info(T, SpacesAccess, Result1);
        true ->
            ListTab = ets:tab2list(subsys_cache),
            AllSpaces = add_subsyses(ListTab, #{}),
            Result1 = Result#{Login => SubSystems#{<<"authHub">> := AllSpaces}},
            parse_users_info(T, SpacesAccess, Result1)
    end;
parse_users_info([{Login, <<"authHub">>, Role, Space} | T], SpacesAccess, Result) ->
    case lists:member(<<"authHub">>, SpacesAccess) of
        true ->
            case maps:get(Login, Result, null) of
                null ->
                    ListTab = ets:tab2list(subsys_cache),
                    Subsystems = add_subsyses(SpacesAccess, #{}),
                    AllSpaces = add_subsyses(ListTab, #{}),
                    Result1 = Result#{Login => Subsystems#{<<"authHub">> => AllSpaces#{Space := [Role]}}},
                    parse_users_info(T, SpacesAccess, Result1);
                #{<<"authHub">> := Spaces} = SubSyses ->
                    case maps:get(Space, Spaces, null) of
                        null ->
                            ListTab = ets:tab2list(subsys_cache),
                            AllSpaces = add_subsyses(ListTab, #{}),
                            Result1 = Result#{Login := SubSyses#{<<"authHub">> := AllSpaces#{Space := [Role]}}},
                            parse_users_info(T, SpacesAccess, Result1);
                        Roles ->
                            Result1 = Result#{Login := SubSyses#{<<"authHub">> := Spaces#{Space := [Role | Roles]}}},
                            parse_users_info(T, SpacesAccess, Result1)
                    end
            end;
        false ->
            parse_users_info(T, SpacesAccess, Result)
    end;
parse_users_info([{Login, SubSys, Role, _Space} | T], SpacesAccess, Result) ->
    case lists:member(SubSys, SpacesAccess) of
        true ->
            case maps:get(Login, Result, null) of
                null ->
                    SubSystems = add_subsyses(SpacesAccess, #{}),
                    Result1 = Result#{Login => SubSystems#{SubSys => [Role]}},
                    parse_users_info(T, SpacesAccess, Result1);
                #{SubSys := Roles} = SubSyses ->
                    Result1 = Result#{Login := SubSyses#{SubSys := [Role | Roles]}},
                    parse_users_info(T, SpacesAccess, Result1)
            end;
        false ->
            parse_users_info(T, SpacesAccess, Result)
    end.

-spec add_subsyses(list(), map()) -> map().
add_subsyses([], Result) -> Result;
add_subsyses([{SubSys} | T], Result) ->
    Result1 = Result#{SubSys => []},
    add_subsyses(T, Result1);
add_subsyses([SubSys | T], Result) ->
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


%% ========= add_roles ====== /api/roles/change =========

-spec handler_add_roles(list(), list()) -> list().
handler_add_roles([], _SpacesAccess) -> [];
handler_add_roles([#{<<"login">> := Login, <<"subsystem">> := <<"authHub">>, <<"roles">> := Roles, <<"space">> := Space} = MapReq | T], SpacesAccess) ->
    case auth_hub_tools:validation(change_roles, {Login, <<"authHub">>, Roles, Space, SpacesAccess}) of
        no_access ->
            ?LOG_ERROR("handler_add_roles no access to space ~p", [<<"authHub">>]),
            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"no access to this space">>},
            [MapResp | handler_add_roles(T, SpacesAccess)];
        false ->
            ?LOG_ERROR("handler_add_roles invalid params value", []),
            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"invalid params value">>},
            [MapResp | handler_add_roles(T, SpacesAccess)];
        true ->
            case generate_insert_sql(first, Roles, Login, <<"authHub">>, Space, ?SQL_INSERT_ROLES) of
                null ->
                    MapResp = MapReq#{<<"success">> => true},
                    [MapResp | handler_add_roles(T, SpacesAccess)];
                Sql ->
                    MapResp = insert_role_to_db(Sql, MapReq),
                    [MapResp | handler_add_roles(T, SpacesAccess)]
            end
    end;
handler_add_roles([#{<<"login">> := Login, <<"subsystem">> := SubSys, <<"roles">> := Roles} = MapReq | T], SpacesAccess) when SubSys =/= <<"authHub">> ->
    case auth_hub_tools:validation(change_roles, {Login, SubSys, Roles, SubSys, SpacesAccess}) of
        no_access ->
            ?LOG_ERROR("handler_add_roles no access to space ~p", [SubSys]),
            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"no access to this space">>},
            [MapResp | handler_add_roles(T, SpacesAccess)];
        false ->
            ?LOG_ERROR("handler_add_roles invalid params value", []),
            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"invalid params value">>},
            [MapResp | handler_add_roles(T, SpacesAccess)];
        true ->
            case generate_insert_sql(first, Roles, Login, SubSys, SubSys, ?SQL_INSERT_ROLES) of
                null ->
                    MapResp = MapReq#{<<"success">> => true},
                    [MapResp | handler_add_roles(T, SpacesAccess)];
                Sql ->
                    MapResp = insert_role_to_db(Sql, MapReq),
                    [MapResp | handler_add_roles(T, SpacesAccess)]
            end
    end;
handler_add_roles([MapReq | T], SpacesAccess) ->
    ?LOG_ERROR("handler_add_roles absent needed params, ~p", [MapReq]),
    MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"absent needed params">>},
    [MapResp | handler_add_roles(T, SpacesAccess)].

-spec insert_role_to_db(string(), map()) -> map().
insert_role_to_db(Sql, MapReq) ->
    case auth_hub_pg:sql_req_not_prepared(Sql, []) of
        {error, {_, _, _, unique_violation, _, _} = Reason} ->
            ?LOG_ERROR("handler_change_roles user have one of this roles, ~p", [Reason]),
            MapReq#{<<"success">> => false, <<"reason">> => <<"user have one of this roles">>};
        {error, {_, _, _, foreign_key_violation, _, _} = Reason} ->
            ?LOG_ERROR("handler_change_roles invalid login, ~p", [Reason]),
            MapReq#{<<"success">> => false, <<"reason">> => <<"invalid params value">>};
        {error, Reason} ->
            ?LOG_ERROR("handler_change_roles db error ~p", [Reason]),
            MapReq#{<<"success">> => false, <<"reason">> => <<"invalid db resp">>};
        {ok, _Count} ->
            MapReq#{<<"success">> => true}
    end.

-spec generate_insert_sql(first | second, list(), binary(), binary(), binary(), string()) -> string() | null.
generate_insert_sql(first, [], _Login, _Subsys, _Space, _Sql) -> null;
generate_insert_sql(second, [], _Login, _Subsys, _Space, Sql) ->
    ?LOG_DEBUG("Insert roles sql ~p", [Sql ++ ")"]),
    Sql;
generate_insert_sql(first, [Role | T], Login, Subsys, Space, Sql) ->
    Sql1 = Sql ++ "('" ++ binary_to_list(Login) ++ "', '" ++
        binary_to_list(Subsys) ++ "', '" ++ binary_to_list(Role) ++  "', '" ++ binary_to_list(Space) ++ "')",
    generate_insert_sql(second, T, Login, Subsys, Space, Sql1);
generate_insert_sql(second, [Role | T], Login, Subsys, Space, Sql) ->
    Sql1 = Sql ++ ", ('" ++ binary_to_list(Login) ++ "', '" ++
        binary_to_list(Subsys) ++ "', '" ++ binary_to_list(Role) ++  "', '" ++ binary_to_list(Space) ++ "')",
    generate_insert_sql(second, T, Login, Subsys, Space, Sql1).


%% ========= remove_roles ====== /api/roles/change =========

-spec remove_roles_handler(list(), list()) -> list().
remove_roles_handler([], _SpacesAccess) -> [];
remove_roles_handler([#{<<"login">> := Login, <<"subsystem">> := <<"authHub">>, <<"roles">> := Roles, <<"space">> := Space} = MapReq | T], SpacesAccess) ->
    case auth_hub_tools:validation(change_roles, {Login, <<"authHub">>, Roles, Space, SpacesAccess}) of
        no_access ->
            ?LOG_ERROR("remove_roles_handler no access to space ~p", [<<"authHub">>]),
            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"no access to this space">>},
            [MapResp | handler_add_roles(T, SpacesAccess)];
        false ->
            ?LOG_ERROR("remove_roles_handler invalid params value", []),
            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"invalid params value">>},
            [MapResp | remove_roles_handler(T, SpacesAccess)];
        true ->
            LoginStr = binary_to_list(Login),
            SpaceStr = binary_to_list(Space),
            case generate_delete_sql(first, Roles, ?SQL_DELETE_ROLES(LoginStr, "authHub", SpaceStr), {Login, <<"authHub">>, Space}) of
                null ->
                    MapResp = MapReq#{<<"success">> => true},
                    [MapResp | remove_roles_handler(T, SpacesAccess)];
                admin_error ->
                    MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"root role 'am'">>},
                    [MapResp | remove_roles_handler(T, SpacesAccess)];
                Sql ->
                    case auth_hub_pg:sql_req_not_prepared(Sql, []) of
                        {error, Reason} ->
                            ?LOG_ERROR("remove_roles_handler db error ~p", [Reason]),
                            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"invalid db resp">>},
                            [MapResp | remove_roles_handler(T, SpacesAccess)];
                        {ok, _Count} ->
                            MapResp = MapReq#{<<"success">> => true},
                            [MapResp | remove_roles_handler(T, SpacesAccess)]
                    end
            end
    end;
remove_roles_handler([#{<<"login">> := Login, <<"subsystem">> := SubSys, <<"roles">> := Roles} = MapReq | T], SpacesAccess) when SubSys =/= <<"authHub">>->
    case auth_hub_tools:validation(change_roles, {Login, SubSys, Roles, SubSys, SpacesAccess}) of
        no_access ->
            ?LOG_ERROR("remove_roles_handler no access to space ~p", [SubSys]),
            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"no access to this space">>},
            [MapResp | handler_add_roles(T, SpacesAccess)];
        false ->
            ?LOG_ERROR("remove_roles_handler invalid params value", []),
            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"invalid params value">>},
            [MapResp | remove_roles_handler(T, SpacesAccess)];
        true ->
            LoginStr = binary_to_list(Login),
            SubSysStr = binary_to_list(SubSys),
            case generate_delete_sql(first, Roles, ?SQL_DELETE_ROLES(LoginStr, SubSysStr, SubSysStr), {Login, SubSys, SubSys}) of
                null ->
                    MapResp = MapReq#{<<"success">> => true},
                    [MapResp | remove_roles_handler(T, SpacesAccess)];
                admin_error ->
                    MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"root role 'am'">>},
                    [MapResp | remove_roles_handler(T, SpacesAccess)];
                Sql ->
                    case auth_hub_pg:sql_req_not_prepared(Sql, []) of
                        {error, Reason} ->
                            ?LOG_ERROR("remove_roles_handler db error ~p", [Reason]),
                            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"invalid db resp">>},
                            [MapResp | remove_roles_handler(T, SpacesAccess)];
                        {ok, _Count} ->
                            MapResp = MapReq#{<<"success">> => true},
                            [MapResp | remove_roles_handler(T, SpacesAccess)]
                    end
            end
    end;
remove_roles_handler([MapReq | T], SpacesAccess) ->
    ?LOG_ERROR("remove_roles_handler absent needed params ~p", [MapReq]),
    MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"absent needed params">>},
    [MapResp | remove_roles_handler(T, SpacesAccess)].


-spec generate_delete_sql(first | second, list(), string(), {binary(), binary(), binary()}) -> string() | null | admin_error.
generate_delete_sql(first, [], _Sql, _AdminCase) -> null;
generate_delete_sql(_FirstFlag, [<<"am">> | _T], _Sql, {<<"admin">>, <<"authHub">>, <<"authHub">>}) ->
    admin_error;
generate_delete_sql(second, [], Sql, _AdminCase) ->
    ?LOG_DEBUG("Delete roles sql ~p", [Sql ++ ")"]),
    Sql ++ ")";
generate_delete_sql(first, [Role | T], Sql, AdminCase) ->
    Sql1 = Sql ++ "role='" ++ binary_to_list(Role) ++ "'",
    generate_delete_sql(second, T, Sql1, AdminCase);
generate_delete_sql(second, [Role | T], Sql, AdminCase) ->
    Sql1 = Sql ++ " or role='" ++ binary_to_list(Role) ++ "'",
    generate_delete_sql(second, T, Sql1, AdminCase).

