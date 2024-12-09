-module(auth_hub_api_allow).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').

-export([create_subsystems/2, delete_roles/2, create_roles/2, get_allow_roles/1]).
-export([delete_subsystems/2]).

-include("auth_hub.hrl").


%% ========= delete_subsystems ====== /api/allow/subsystems/change =========

-spec delete_subsystems(map(), list()) -> {integer(), map()}.
delete_subsystems(#{<<"subsystems">> := Subsystems}, SpacesAccess) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {429, ?RESP_FAIL(<<"too many requests">>)};
        PgPid ->
            Resp = delete_subsystems(Subsystems, PgPid, SpacesAccess),
            ok = poolboy:checkin(pg_pool, PgPid),
            {200, #{<<"results">> => Resp}}
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("No workers in pg_pool ~p", [Reason]),
            {429, ?RESP_FAIL(<<"too many requests">>)}
    end;
delete_subsystems(OtherBody, _SpacesAccess) ->
    ?LOG_ERROR("delete_subsystems invalid request format ~p", [OtherBody]),
    {422, ?RESP_FAIL(<<"invalid request format">>)}.

-spec delete_subsystems(list(), pid(), list()) -> list().
delete_subsystems([], _, _) -> [];
delete_subsystems([<<"authHub">> | T], PgPid, SpacesAccess) ->
    Resp = #{<<"success">> => false, <<"reason">> => <<"root subsystem">>, <<"subsystem">> => <<"authHub">>},
    [Resp | delete_subsystems(T, PgPid, SpacesAccess)];
delete_subsystems([SubSys | T], PgPid, SpacesAccess) ->
    case lists:member(SubSys, SpacesAccess) of
        true ->
            case auth_hub_pg:select(PgPid, "delete_subsystem", [SubSys]) of
                {error, Reason} ->
                    ?LOG_ERROR("delete_subsystems db error ~p", [Reason]),
                    Resp = #{<<"success">> => false, <<"reason">> => <<"invalid db response">>, <<"subsystem">> => SubSys},
                    [Resp | delete_subsystems(T, PgPid, SpacesAccess)];
                {ok, _, [{<<"ok">>}]} ->
                    Resp = #{<<"success">> => true, <<"subsystem">> => SubSys},
                    true = ets:delete(subsys_cache, SubSys),
                    [Resp | delete_subsystems(T, PgPid, SpacesAccess)]
            end;
        false ->
            ?LOG_ERROR("delete_subsystems no accept to space ~p", [SubSys]),
            Resp = #{<<"success">> => false, <<"reason">> => <<"no accept to this space">>, <<"subsystem">> => SubSys},
            [Resp | delete_subsystems(T, PgPid, SpacesAccess)]
    end.


%% ========= create_subsystems ====== /api/allow/subsystems/change =========

-spec create_subsystems(map(), list()) -> {integer(), map()}.
create_subsystems(#{<<"subsystems">> := Subsystems}, SpacesAccess) when is_list(Subsystems) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {429, ?RESP_FAIL(<<"too many requests">>)};
        PgPid ->
            Resp = create_subsys_handler(Subsystems, PgPid, SpacesAccess),
            ok = poolboy:checkin(pg_pool, PgPid),
            {200, #{<<"results">> => Resp}}
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("No workers in pg_pool ~p", [Reason]),
            {429, ?RESP_FAIL(<<"too many requests">>)}
    end;
create_subsystems(OtherBody, _) ->
    ?LOG_ERROR("create_subsystems invalid request format ~p", [OtherBody]),
    {422, ?RESP_FAIL(<<"invalid request format">>)}.

-spec create_subsys_handler(list(), pid(), list()) -> list().
create_subsys_handler([], _, _) -> [];
create_subsys_handler([#{<<"subsystem">> := SubSys, <<"description">> := Desc} | T], PgPid, SpacesAccess) ->
    case auth_hub_tools:validation(create_subsystems, {SubSys, Desc, SpacesAccess}) of
        true ->
            case auth_hub_pg:select(PgPid, "insert_allow_subsystem", [SubSys, Desc]) of
                {error, {_, _, _, unique_violation, _, _} = Reason} ->
                    ?LOG_ERROR("create_subsystems user have one of this roles, ~p", [Reason]),
                    Resp = #{<<"success">> => false, <<"reason">> => <<"subsystem exists">>, <<"subsystem">> => SubSys},
                    [Resp | create_subsys_handler(T, PgPid, SpacesAccess)];
                {error, Reason} ->
                    ?LOG_ERROR("create_subsystems db error ~p", [Reason]),
                    Resp = #{<<"success">> => false, <<"reason">> => <<"invalid db response">>, <<"subsystem">> => SubSys},
                    [Resp | create_subsys_handler(T, PgPid, SpacesAccess)];
                {ok, _, [{<<"ok">>}]} ->
                    Resp = #{<<"success">> => true, <<"subsystem">> => SubSys},
                    true = ets:insert(subsys_cache, {SubSys}),
                    ok = insert_subsys_in_admin_sids_cache(SubSys),
                    [Resp | create_subsys_handler(T, PgPid, SpacesAccess)]
            end;
        false ->
            ?LOG_ERROR("create_subsystems invalid params ~p", [{SubSys, Desc}]),
            Resp = #{<<"success">> => false, <<"reason">> => <<"invalid params">>, <<"subsystem">> => SubSys},
            [Resp | create_subsys_handler(T, PgPid, SpacesAccess)]
    end;
create_subsys_handler([MapReq | T], PgPid, SpacesAccess) ->
    ?LOG_ERROR("create_subsystems absent needed params, ~p", [MapReq]),
    MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"absent needed params">>},
    [MapResp | create_subsys_handler(T, PgPid, SpacesAccess)].

-spec insert_subsys_in_admin_sids_cache(binary()) -> ok.
insert_subsys_in_admin_sids_cache(SubSys) ->
    SidCache = ets:select(sids_cache, [{
        {'$1', '$2', '$3', '$4'},
        [{'=:=', '$2', <<"admin">>}],
        ['$1']
    }]),
    case SidCache of
        [] ->
            ok;
        [Sid] ->
            [{Sid, Login, RolesMap, DateEnd}] = ets:tab2list(sids_cache),
            #{<<"authHub">> := RolesSpaces} = RolesMap,
            RolesSpaces1 = RolesSpaces#{SubSys => [<<"am">>]},
            RolesMap1 = RolesMap#{<<"authHub">> := RolesSpaces1},
            true = ets:insert(sids_cache, {Sid, Login, RolesMap1, DateEnd}),
            ok
    end.

%% ========= delete_roles ====== /api/allow/roles/change =========

-spec delete_roles(map(), list()) -> {integer(), map()}.
delete_roles(#{<<"subsys_roles">> := DelRolesMap}, SpacesAccess) when is_map(DelRolesMap) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {429, ?RESP_FAIL(<<"too many requests">>)};
        PgPid ->
            ListSubSys = maps:keys(DelRolesMap),
            Resp = delete_roles_handler(ListSubSys, DelRolesMap, PgPid, SpacesAccess),
            ok = poolboy:checkin(pg_pool, PgPid),
            {200, #{<<"results">> => Resp}}
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("No workers in pg_pool ~p", [Reason]),
            {429, ?RESP_FAIL(<<"too many requests">>)}
    end;
delete_roles(OtherBody, _) ->
    ?LOG_ERROR("delete_roles invalid request format ~p", [OtherBody]),
    {422, ?RESP_FAIL(<<"invalid request format">>)}.


-spec delete_roles_handler(list(), binary(), binary(), list()) -> list().
delete_roles_handler([], _DelRolesMap, _PgPid, _) -> [];
delete_roles_handler([SubSys | T], DelRolesMap, PgPid, SpacesAccess) ->
    #{SubSys := ListRoles} = DelRolesMap,
    case {lists:member(SubSys, SpacesAccess), auth_hub_tools:valid_roles(ListRoles)} of
        {false, _} ->
            ?LOG_ERROR("delete_roles no access to space ~p", [SubSys]),
            Resp = #{<<"reason">> => <<"no access to this space">>, <<"success">> => false, <<"subsystem">> => SubSys, <<"roles">> => ListRoles},
            [Resp | delete_roles_handler(T, DelRolesMap, PgPid, SpacesAccess)];
        {_, false} ->
            ?LOG_ERROR("delete_roles invalid roles ~p, ~p", [SubSys, ListRoles]),
            Resp = #{<<"reason">> => <<"invalid roles">>, <<"success">> => false, <<"subsystem">> => SubSys, <<"roles">> => ListRoles},
            [Resp | delete_roles_handler(T, DelRolesMap, PgPid, SpacesAccess)];
        {true, true} ->
            ListResp = delete_roles_db(ListRoles, SubSys, PgPid),
            ListResp ++ delete_roles_handler(T, DelRolesMap, PgPid, SpacesAccess)
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

-spec create_roles(map(), list()) -> {integer(), map()}.
create_roles(#{<<"roles">> := RolesList}, SpacesAccess) when is_list(RolesList) ->
    try poolboy:checkout(pg_pool, 1000) of
        full ->
            ?LOG_ERROR("No workers in pg_pool", []),
            {429, ?RESP_FAIL(<<"too many requests">>)};
        PgPid ->
            Resp = create_roles_handler(RolesList, PgPid, SpacesAccess),
            ok = poolboy:checkin(pg_pool, PgPid),
            {200, #{<<"results">> => Resp}}
    catch
        exit:{timeout, Reason} ->
            ?LOG_ERROR("No workers in pg_pool ~p", [Reason]),
            {429, ?RESP_FAIL(<<"too many requests">>)}
    end;
create_roles(OtherBody, _) ->
    ?LOG_ERROR("create_roles invalid request format ~p", [OtherBody]),
    {422, ?RESP_FAIL(<<"invalid request format">>)}.


-spec create_roles_handler(list(), pid(), list()) -> list().
create_roles_handler([], _, _) -> [];
create_roles_handler([#{<<"role">> := Role, <<"subsystem">> := SubSys, <<"description">> := Desc} | T], PgPid, SpacesAccess) ->
    case auth_hub_tools:validation(create_roles, {SubSys, Role, Desc, SpacesAccess}) of
        true ->
            case auth_hub_pg:insert(PgPid, "insert_allow_role", [SubSys, Role, Desc]) of
                {error, {_, _, _, unique_violation, _, _} = Reason} ->
                    ?LOG_ERROR("create_roles user have one of this roles, ~p", [Reason]),
                    Resp = #{<<"success">> => false, <<"reason">> => <<"subsystem exists">>,
                        <<"role">> => Role, <<"subsystem">> => SubSys},
                    [Resp | create_roles_handler(T, PgPid, SpacesAccess)];
                {error, Reason} ->
                    ?LOG_ERROR("create_roles_handler db error ~p", [Reason]),
                    Resp = #{<<"success">> => false, <<"reason">> => <<"invalid db response">>,
                        <<"role">> => Role, <<"subsystem">> => SubSys},
                    [Resp | create_roles_handler(T, PgPid, SpacesAccess)];
                {ok, 1} ->
                    Resp = #{<<"success">> => true, <<"role">> => Role, <<"subsystem">> => SubSys},
                    [Resp | create_roles_handler(T, PgPid, SpacesAccess)]
            end;
        no_access ->
            ?LOG_ERROR("create_roles_handler no access to space ~p", [{SubSys}]),
            Resp = #{<<"success">> => false, <<"reason">> => <<"no access to this space">>,
                <<"role">> => Role, <<"subsystem">> => SubSys},
            [Resp | create_roles_handler(T, PgPid, SpacesAccess)];
        false ->
            ?LOG_ERROR("create_roles_handler invalid params ~p", [{Role, SubSys, Desc}]),
            Resp = #{<<"success">> => false, <<"reason">> => <<"invalid params">>,
                <<"role">> => Role, <<"subsystem">> => SubSys},
            [Resp | create_roles_handler(T, PgPid, SpacesAccess)]
    end;
create_roles_handler([MapReq | T], PgPid, SpacesAccess) ->
    ?LOG_ERROR("create_roles_handler absent needed params ~p", [MapReq]),
    MapResp = MapReq#{<<"success">> => false, <<"reason">> => <<"absent needed params">>},
    [MapResp | create_roles_handler(T, PgPid, SpacesAccess)].


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

