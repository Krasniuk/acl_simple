-module(auth_hub_api_allow).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').

-export([create_subsystems/1, delete_roles/1, create_roles/1, get_allow_roles/1, change_roles/2]).
-export([delete_subsystems/1]).

-include("auth_hub.hrl").


%% ========= delete_subsystems ====== /api/allow/subsystems/change =========

-spec delete_subsystems(map()) -> {integer(), map()}.
delete_subsystems(#{<<"subsystems">> := Subsystems}) ->
    case auth_hub_tools:valid_subsystems(Subsystems) of
        true ->
            try poolboy:checkout(pg_pool, 1000) of
                full ->
                    ?LOG_ERROR("No workers in pg_pool", []),
                    {429, ?RESP_FAIL(<<"too many requests">>)};
                PgPid ->
                    Resp = delete_subsystems(Subsystems, PgPid),
                    ok = poolboy:checkin(pg_pool, PgPid),
                    {200, #{<<"results">> => Resp}}
            catch
                exit:{timeout, Reason} ->
                    ?LOG_ERROR("No workers in pg_pool ~p", [Reason]),
                    {429, ?RESP_FAIL(<<"too many requests">>)}
            end;
        false ->
            ?LOG_ERROR("delete_subsystems invalid subsystems ~p", [{Subsystems}]),
            {422, ?RESP_FAIL(<<"invalid subsystems">>)}
    end;
delete_subsystems(OtherBody) ->
    ?LOG_ERROR("create_subsystems invalid request format ~p", [OtherBody]),
    {422, ?RESP_FAIL(<<"invalid request format">>)}.

-spec delete_subsystems(list(), pid()) -> list().
delete_subsystems([], _) -> [];
delete_subsystems([<<"authHub">> | T], PgPid) ->
    Resp = #{<<"success">> => false, <<"reason">> => <<"root subsystem">>, <<"subsystem">> => <<"authHub">>},
    [Resp | delete_subsystems(T, PgPid)];
delete_subsystems([SubSys | T], PgPid) ->
    case auth_hub_pg:select(PgPid, "delete_subsystem", [SubSys]) of
        {error, Reason} ->
            ?LOG_ERROR("create_subsystems db error ~p", [Reason]),
            Resp = #{<<"success">> => false, <<"reason">> => <<"invalid db response">>, <<"subsystem">> => SubSys},
            [Resp | delete_subsystems(T, PgPid)];
        {ok, _, [{<<"ok">>}]} ->
            Resp = #{<<"success">> => true, <<"subsystem">> => SubSys},
            true = ets:delete(subsys_cache, SubSys),
            [Resp | delete_subsystems(T, PgPid)]
    end.


%% ========= create_subsystems ====== /api/allow/subsystems/change =========

-spec create_subsystems(map()) -> {integer(), map()}.
create_subsystems(#{<<"subsystems">> := Subsystems}) when is_list(Subsystems) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {429, ?RESP_FAIL(<<"too many requests">>)};
        PgPid ->
            Resp = create_subsys_handler(Subsystems, PgPid),
            ok = poolboy:checkin(pg_pool, PgPid),
            {200, #{<<"results">> => Resp}}
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("No workers in pg_pool ~p", [Reason]),
            {429, ?RESP_FAIL(<<"too many requests">>)}
    end;
create_subsystems(OtherBody) ->
    ?LOG_ERROR("create_subsystems invalid request format ~p", [OtherBody]),
    {422, ?RESP_FAIL(<<"invalid request format">>)}.

-spec create_subsys_handler(list(), pid()) -> list().
create_subsys_handler([], _) -> [];
create_subsys_handler([#{<<"subsystem">> := SubSys, <<"description">> := Desc} | T], PgPid) ->
    case auth_hub_tools:validation(create_subsystems, {SubSys, Desc}) of
        true ->
            case auth_hub_pg:select(PgPid, "insert_allow_subsystem", [SubSys, Desc]) of
                {error, {_, _, _, unique_violation, _, _} = Reason} ->
                    ?LOG_ERROR("create_subsystems user have one of this roles, ~p", [Reason]),
                    Resp = #{<<"success">> => false, <<"reason">> => <<"role exists">>, <<"subsystem">> => SubSys},
                    [Resp | create_subsys_handler(T, PgPid)];
                {error, Reason} ->
                    ?LOG_ERROR("create_subsystems db error ~p", [Reason]),
                    Resp = #{<<"success">> => false, <<"reason">> => <<"invalid db response">>, <<"subsystem">> => SubSys},
                    [Resp | create_subsys_handler(T, PgPid)];
                {ok, _, [{<<"ok">>}]} ->
                    Resp = #{<<"success">> => true, <<"subsystem">> => SubSys},
                    true = ets:insert(subsys_cache, {SubSys}),
                    [Resp | create_subsys_handler(T, PgPid)]
            end;
        false ->
            ?LOG_ERROR("create_subsystems invalid params ~p", [{SubSys, Desc}]),
            Resp = #{<<"success">> => false, <<"reason">> => <<"invalid params">>, <<"subsystem">> => SubSys},
            [Resp | create_subsys_handler(T, PgPid)]
    end;
create_subsys_handler([MapReq | T], PgPid) ->
    ?LOG_ERROR("create_subsystems absent needed params, ~p", [MapReq]),
    MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"absent needed params">>},
    [MapResp | create_subsys_handler(T, PgPid)].


%% ========= delete_roles ====== /api/allow/roles/change =========

-spec delete_roles(map()) -> {integer(), map()}.
delete_roles(#{<<"subsys_roles">> := DelRolesMap}) when is_map(DelRolesMap) ->
    ListSubSys = maps:keys(DelRolesMap),
    case auth_hub_tools:valid_subsystems(ListSubSys) of
        true ->
            try poolboy:checkout(pg_pool, 1000) of
                full ->
                    ?LOG_ERROR("No workers in pg_pool", []),
                    {429, ?RESP_FAIL(<<"too many requests">>)};
                PgPid ->
                    Resp = delete_roles_handler(ListSubSys, DelRolesMap, PgPid),
                    ok = poolboy:checkin(pg_pool, PgPid),
                    {200, #{<<"results">> => Resp}}
            catch
                exit:{timeout, Reason} ->
                    ?LOG_ERROR("No workers in pg_pool ~p", [Reason]),
                    {429, ?RESP_FAIL(<<"too many requests">>)}
            end;
        false ->
            ?LOG_ERROR("delete_roles invalid subsystems ~p", [ListSubSys]),
            {422, ?RESP_FAIL(<<"invalid subsystem">>)}
    end;
delete_roles(OtherBody) ->
    ?LOG_ERROR("delete_roles invalid request format ~p", [OtherBody]),
    {422, ?RESP_FAIL(<<"invalid request format">>)}.


-spec delete_roles_handler(list(), binary(), binary()) -> list().
delete_roles_handler([], _DelRolesMap, _PgPid) -> [];
delete_roles_handler([SubSys | T], DelRolesMap, PgPid) ->
    #{SubSys := ListRoles} = DelRolesMap,
    case auth_hub_tools:valid_roles(ListRoles) of
        false ->
            ?LOG_ERROR("delete_roles invalid roles ~p, ~p", [SubSys, ListRoles]),
            Resp = #{<<"reason">> => <<"invalid roles">>, <<"success">> => false, <<"subsystem">> => SubSys, <<"roles">> => ListRoles},
            [Resp | delete_roles_handler(T, DelRolesMap, PgPid)];
        true ->
            ListResp = delete_roles_db(ListRoles, SubSys, PgPid),
            ListResp ++ delete_roles_handler(T, DelRolesMap, PgPid)
    end.

-spec delete_roles_db(list(), binary(), binary()) -> list().
delete_roles_db([], _, _) -> [];
delete_roles_db([<<"am">> | T], <<"authHub">> = SubSys, PgPid) ->
    Resp = #{<<"success">> => false, <<"reason">> => <<"root role">>, <<"subsystem">> => SubSys, <<"role">> => <<"am">>},
    [Resp | delete_roles_db(T, SubSys, PgPid)];
delete_roles_db([Role | T], SubSys, PgPid) ->
    case auth_hub_pg:select(PgPid, "delete_allow_role", [SubSys, Role]) of
        {error, Reason} ->
            ?LOG_ERROR("delete_roles_db db error ~p", [Reason]),
            Resp = #{<<"success">> => false, <<"reason">> => <<"invalid db response">>, <<"subsystem">> => SubSys, <<"role">> => Role},
            [Resp | delete_roles_db(T, SubSys, PgPid)];
        {ok, _, [{<<"ok">>}]} ->
            Resp = #{<<"success">> => true, <<"subsystem">> => SubSys, <<"role">> => Role},
            [Resp | delete_roles_db(T, SubSys, PgPid)]
    end.


%% ========= create_roles ====== /api/allow/roles/change =========

-spec create_roles(map()) -> {integer(), map()}.
create_roles(#{<<"roles">> := RolesList}) when is_list(RolesList) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {429, ?RESP_FAIL(<<"too many requests">>)};
        PgPid ->
            Resp = create_roles_handler(RolesList, PgPid),
            ok = poolboy:checkin(pg_pool, PgPid),
            {200, #{<<"results">> => Resp}}
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("No workers in pg_pool ~p", [Reason]),
            {429, ?RESP_FAIL(<<"too many requests">>)}
    end;
create_roles(OtherBody) ->
    ?LOG_ERROR("create_roles invalid request format ~p", [OtherBody]),
    {422, ?RESP_FAIL(<<"invalid request format">>)}.


-spec create_roles_handler(list(), pid()) -> list().
create_roles_handler([], _) -> [];
create_roles_handler([#{<<"role">> := Role, <<"subsystem">> := SubSys, <<"description">> := Desc} | T], PgPid) ->
    case auth_hub_tools:validation(create_roles, {SubSys, Role, Desc}) of
        true ->
            case auth_hub_pg:insert(PgPid, "insert_allow_role", [SubSys, Role, Desc]) of
                {error, {_, _, _, unique_violation, _, _} = Reason} ->
                    ?LOG_ERROR("create_roles user have one of this roles, ~p", [Reason]),
                    Resp = #{<<"success">> => false, <<"reason">> => <<"subsystem exists">>,
                        <<"role">> => Role, <<"subsystem">> => SubSys},
                    [Resp | create_roles_handler(T, PgPid)];
                {error, Reason} ->
                    ?LOG_ERROR("create_roles db error ~p", [Reason]),
                    Resp = #{<<"success">> => false, <<"reason">> => <<"invalid db response">>,
                        <<"role">> => Role, <<"subsystem">> => SubSys},
                    [Resp | create_roles_handler(T, PgPid)];
                {ok, 1} ->
                    Resp = #{<<"success">> => true, <<"role">> => Role, <<"subsystem">> => SubSys},
                    [Resp | create_roles_handler(T, PgPid)]
            end;
        false ->
            ?LOG_ERROR("create_roles invalid params ~p", [{Role, SubSys, Desc}]),
            Resp = #{<<"success">> => false, <<"reason">> => <<"invalid params">>,
                <<"role">> => Role, <<"subsystem">> => SubSys},
            [Resp | create_roles_handler(T, PgPid)]
    end;
create_roles_handler([MapReq | T], PgPid) ->
    ?LOG_ERROR("create_roles absent needed params ~p", [MapReq]),
    MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"absent needed params">>},
    [MapResp | create_roles_handler(T, PgPid)].


%% ========= get_allow_roles ====== /api/roles/allow/info =========

-spec get_allow_roles(list()) -> {integer(), map()}.
get_allow_roles(SpacesAccess) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {429, ?RESP_FAIL(<<"too many requests">>)};
        PgPid ->
            Resp = get_allow_roles(PgPid, SpacesAccess),
            ok = poolboy:checkin(pg_pool, PgPid),
            Resp
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("No workers in pg_pool ~p", [Reason]),
            {429, ?RESP_FAIL(<<"too many requests">>)}
    end.

-spec get_allow_roles(pid(), list()) -> list().
get_allow_roles(PgPid, SpacesAccess) ->
    case auth_hub_pg:select(PgPid, "get_allow_roles", []) of
        {error, Reason} ->
            ?LOG_ERROR("get_allow_roles db error ~p", [Reason]),
            {502, ?RESP_FAIL(<<"invalid db response">>)};
        {ok, _, DbValues} ->
            MapAllRoles = parse_allow_roles(DbValues, #{}),
            case auth_hub_pg:select(PgPid, "get_allow_subsystem", []) of
                {error, Reason} ->
                    ?LOG_ERROR("get_allow_roles db error ~p", [Reason]),
                    {502, ?RESP_FAIL(<<"invalid db response">>)};
                {ok, _, DbValues1} ->
                    MapResp = parse_allow_subsystems(DbValues1, MapAllRoles, SpacesAccess),
                    {200, ?RESP_SUCCESS(MapResp)}
            end
    end.

-spec parse_allow_roles(DbResp :: list(), map()) -> map().
parse_allow_roles([], Result) -> Result;
parse_allow_roles([{SubSys, null, null} | T], Result) ->
    Result1 = Result#{SubSys => []},
    parse_allow_roles(T, Result1);
parse_allow_roles([{SubSys, DbRole, Description} | T], Result) ->
    Result1 = case maps:get(SubSys, Result, null) of
                  null ->
                      Result#{SubSys => [#{<<"role">> => DbRole, <<"description">> => Description}]};
                  Roles ->
                      Result#{SubSys := [#{<<"role">> => DbRole, <<"description">> => Description} | Roles]}
              end,
    parse_allow_roles(T, Result1).

-spec parse_allow_subsystems(DbResp :: list(), map(), list()) -> list().
parse_allow_subsystems([], _MapAllRoles, _SpacesAccess) -> [];
parse_allow_subsystems([{SubSys, Description} | T], MapAllRoles, SpacesAccess) ->
    case lists:member(SubSys, SpacesAccess) of
        true ->
            #{SubSys := Roles} = MapAllRoles,
            MapResp = #{<<"subsystem">> => SubSys, <<"roles">> => Roles, <<"description">> => Description},
            [MapResp | parse_allow_subsystems(T, MapAllRoles, SpacesAccess)];
        false ->
            parse_allow_subsystems(T, MapAllRoles, SpacesAccess)
    end.



%% ========= add_roles, remove_roles ====== /api/roles/change =========

-spec change_roles(binary(), map()) -> {integer(), map()}.
change_roles(Method, #{<<"changes">> := ListOperations}) when
    ((Method =:= <<"add_roles">>) or (Method =:= <<"remove_roles">>)) and is_list(ListOperations) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {429, ?RESP_FAIL(<<"too many requests">>)};
        WorkerPid ->
            Reply = handler_change_roles(Method, ListOperations),
            ok = poolboy:checkin(pg_pool, WorkerPid),
            {200, #{<<"results">> => Reply}}
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("No workers in pg_pool ~p", [Reason]),
            {429, ?RESP_FAIL(<<"too many requests">>)}
    end;
change_roles(Method, OtherBody) ->
    ?LOG_ERROR("change_roles invalid request format ~p, ~p", [Method, OtherBody]),
    {422, ?RESP_FAIL(<<"invalid request format">>)}.


-spec handler_change_roles(binary(), list()) -> list().
handler_change_roles(_Method, []) -> [];
handler_change_roles(<<"add_roles">>, [#{<<"login">> := Login, <<"subsystem">> := SubSys, <<"roles">> := Roles} = MapReq | T]) ->
    case auth_hub_tools:validation(change_roles, {Login, SubSys, Roles}) of
        false ->
            ?LOG_ERROR("handler_change_roles invalid params value", []),
            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"invalid params value">>},
            [MapResp | handler_change_roles(<<"add_roles">>, T)];
        true ->
            case generate_insert_sql(first, Roles, Login, SubSys, ?SQL_INSERT_ROLES) of
                null ->
                    MapResp = MapReq#{<<"success">> => true},
                    [MapResp | handler_change_roles(<<"add_roles">>, T)];
                Sql ->
                    case auth_hub_pg:sql_req_not_prepared(Sql, []) of
                        {error, {_, _, _, unique_violation, _, _} = Reason} ->
                            ?LOG_ERROR("handler_change_roles user have one of this roles, ~p", [Reason]),
                            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"user have one of this roles">>},
                            [MapResp | handler_change_roles(<<"add_roles">>, T)];
                        {error, {_, _, _, foreign_key_violation, _, _} = Reason} ->
                            ?LOG_ERROR("handler_change_roles invalid login, ~p", [Reason]),
                            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"invalid params value">>},
                            [MapResp | handler_change_roles(<<"add_roles">>, T)];
                        {error, Reason} ->
                            ?LOG_ERROR("handler_change_roles db error ~p", [Reason]),
                            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"invalid db resp">>},
                            [MapResp | handler_change_roles(<<"add_roles">>, T)];
                        {ok, _Count} ->
                            MapResp = MapReq#{<<"success">> => true},
                            [MapResp | handler_change_roles(<<"add_roles">>, T)]
                    end
            end
    end;
handler_change_roles(<<"remove_roles">>, [#{<<"login">> := Login, <<"subsystem">> := SubSys, <<"roles">> := Roles} = MapReq | T]) ->
    case auth_hub_tools:validation(change_roles, {Login, SubSys, Roles}) of
        false ->
            ?LOG_ERROR("handler_change_roles invalid params value", []),
            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"invalid params value">>},
            [MapResp | handler_change_roles(<<"remove_roles">>, T)];
        true ->
            LoginStr = binary_to_list(Login),
            SubSysStr = binary_to_list(SubSys),
            case generate_delete_sql(first, Roles, ?SQL_DELETE_ROLES(LoginStr, SubSysStr), {Login, SubSys}) of
                null ->
                    MapResp = MapReq#{<<"success">> => true},
                    [MapResp | handler_change_roles(<<"remove_roles">>, T)];
                admin_error ->
                    MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"root role 'am'">>},
                    [MapResp | handler_change_roles(<<"remove_roles">>, T)];
                Sql ->
                    case auth_hub_pg:sql_req_not_prepared(Sql, []) of
                        {error, Reason} ->
                            ?LOG_ERROR("handler_change_roles db error ~p", [Reason]),
                            MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"invalid db resp">>},
                            [MapResp | handler_change_roles(<<"remove_roles">>, T)];
                        {ok, _Count} ->
                            MapResp = MapReq#{<<"success">> => true},
                            [MapResp | handler_change_roles(<<"remove_roles">>, T)]
                    end
            end
    end;
handler_change_roles(Method, [MapReq | T]) ->
    ?LOG_ERROR("handler_change_roles absent needed params, ~p", [MapReq]),
    MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"absent needed params">>},
    [MapResp | handler_change_roles(Method, T)].

-spec generate_delete_sql(first | second, list(), string(), {binary(), binary()}) -> string() | null | admin_error.
generate_delete_sql(first, [], _Sql, _AdminCase) -> null;
generate_delete_sql(_FirstFlag, [<<"am">> | _T], _Sql, {<<"admin">>, <<"authHub">>}) ->
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

-spec generate_insert_sql(first | second, list(), binary(), binary(), string()) -> string() | null.
generate_insert_sql(first, [], _Login, _Subsys, _Sql) -> null;
generate_insert_sql(second, [], _Login, _Subsys, Sql) ->
    ?LOG_DEBUG("Insert roles sql ~p", [Sql ++ ")"]),
    Sql;
generate_insert_sql(first, [Role | T], Login, Subsys, Sql) ->
    Sql1 = Sql ++ "('" ++ binary_to_list(Login) ++ "', '" ++ binary_to_list(Subsys) ++ "', '" ++ binary_to_list(Role) ++ "')",
    generate_insert_sql(second, T, Login, Subsys, Sql1);
generate_insert_sql(second, [Role | T], Login, Subsys, Sql) ->
    Sql1 = Sql ++ ", ('" ++ binary_to_list(Login) ++ "', '" ++ binary_to_list(Subsys) ++ "', '" ++ binary_to_list(Role) ++ "')",
    generate_insert_sql(second, T, Login, Subsys, Sql1).

