-module(auth_hub_auth_handler).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').

-export([init/2]).

-include("auth_hub.hrl").


init(Req, [ActionKey]) ->
    Method = cowboy_req:method(Req),
    HasBody = cowboy_req:has_body(Req),
    Resp = handle_post(Method, HasBody, Req, ActionKey),
    {ok, Resp, [ActionKey]}.

-spec handle_post(binary(), boolean(), list(), get_roles|get_ldap) -> term().
handle_post(<<"POST">>, true, Req, get_roles) ->
    {ok, Body, _Req} = cowboy_req:read_body(Req),
    Sid = cowboy_req:header(<<"sid">>, Req, undefined),
    ?LOG_DEBUG("Post request ~p", [Body]),
    {HttpCode, RespMap} = handle_req(Body, Sid),
    ?LOG_DEBUG("Post reply ~p", [HttpCode]),
    RespBody = jsone:encode(RespMap),
    cowboy_req:reply(HttpCode, #{<<"content-type">> => <<"application/json; charset=UTF-8">>}, RespBody, Req);
handle_post(<<"GET">>, _, Req, get_ldap) ->
    Sid = cowboy_req:header(<<"sid">>, Req, undefined),
    ?LOG_DEBUG("Get request get_ldap, sid  ~p", [<<Sid:4/binary, "...">>]),
    {HttpCode, RespMap} = handle_req(Sid),
    ?LOG_DEBUG("Get reply ~p", [HttpCode]),
    RespBody = jsone:encode(RespMap),
    cowboy_req:reply(HttpCode, #{<<"content-type">> => <<"application/json; charset=UTF-8">>}, RespBody, Req);
handle_post(<<"POST">>, false, Req, _ActionKey) ->
    ?LOG_ERROR("Missing body ~p~n", [Req]),
    cowboy_req:reply(400, #{}, <<"Missing body.">>, Req);
handle_post(Method, _, Req, _ActionKey) ->
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
handle_body(Body, RolesMap) ->
    case jsone:try_decode(Body) of
        {error, Reason} ->
            ?LOG_ERROR("Decode error, ~p", [Reason]),
            {400, ?RESP_FAIL(<<"invalid request format">>)};
        {ok, #{<<"subsystem">> := SubSys}, _} ->
            case ets:member(subsys_cache, SubSys) of
                true ->
                    RolesList = maps:get(SubSys, RolesMap, []),
                    {200, ?RESP_SUCCESS_ROLES(SubSys, RolesList)};
                false ->
                    {400, ?RESP_FAIL(<<"invalid param subsystem">>)}
            end;
        {ok, OtherMap, _} ->
            ?LOG_ERROR("Absent needed params ~p", [OtherMap]),
            {422, ?RESP_FAIL(<<"absent needed params">>)}
    end.

%% ============ get_ldap ============

-spec handle_req(binary()|undefined) -> {integer(), map()}.
handle_req(Sid) ->
    case auth_hub_helper:check_sid(Sid) of
        {Sid, Login, _RolesMap, _TsEnd} ->
            {200, ?RESP_SUCCESS_LOGIN(Login)};
        _Error ->
            ?LOG_ERROR("sid is invalid or legacy", []),
            {403, ?RESP_FAIL(<<"sid is invalid or legacy">>)}
    end.