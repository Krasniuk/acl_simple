-module(auth_hub_req_sid).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').

-export([init/2]).

-include("auth_hub.hrl").

-spec init(map(), list()) -> tuple().
init(Req, [open_session] = Opts) ->
    Method = cowboy_req:method(Req),
    HasBody = cowboy_req:has_body(Req),
    Resp = handle_post(Method, HasBody, Req),
    {ok, Resp, Opts};
init(Req, [check_sid] = Opts) ->
    Method = cowboy_req:method(Req),
    Resp = handle_get(Method, Req),
    {ok, Resp, Opts}.


%% ========= open_session =========

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
    {Status, RespMap} = handle_body(Body),
    RespBody = jsone:encode(RespMap),
    ?LOG_DEBUG("Post reply ~p", [Status]),
    cowboy_req:reply(Status, #{<<"content-type">> => <<"application/json; charset=UTF-8">>}, RespBody, Req).

-spec handle_body(binary()) -> {integer(), map()}.
handle_body(Body) ->
    case jsone:try_decode(Body) of
        {error, Reason} ->
            ?LOG_ERROR("Decode error, ~p", [Reason]),
            {400, ?RESP_FAIL(<<"invalid request format">>)};
        {ok, #{<<"login">> := Login, <<"pass">> := PassWord}, _} ->
            get_session(Login, PassWord);
        _OtherMap ->
            ?LOG_ERROR("Absent needed params", []),
            {422, ?RESP_FAIL(<<"absent needed params">>)}
    end.

-spec get_session(binary(), binary()) -> {integer(), map()}.
get_session(Login, PassWord) ->
    case auth_hub_pg:select("get_passhash", [Login]) of
        {error, Reason} ->
            ?LOG_ERROR("Db error ~p", [Reason]),
            {403, ?RESP_FAIL(<<"invalid password or login">>)};
        {ok, _, [{PermitHash}]} ->
            [{salt, Salt}] = ets:lookup(opts, salt),
            SaltBin = list_to_binary(Salt),
            PassHash = io_lib:format("~64.16.0b", [binary:decode_unsigned(crypto:pbkdf2_hmac(sha256, PassWord, SaltBin, 4000, 32))]),
            case binary_to_list(PermitHash) =:= PassHash of
                true ->
                    Ts = calendar:local_time(),
                    TsStart = auth_hub_tools:ts_to_bin(Ts),
                    TsSec = calendar:datetime_to_gregorian_seconds(Ts),
                    DateEnd = calendar:gregorian_seconds_to_datetime(TsSec + 1800),
                    TsEnd = auth_hub_tools:ts_to_bin(DateEnd),
                    case create_sid(Login, DateEnd) of
                        error ->
                            {502, ?RESP_FAIL(<<"invalid db response">>)};
                        Sid ->
                            {200, ?RESP_SUCCESS_SID(Sid, TsStart, TsEnd)}
                    end;
                false ->
                    ?LOG_ERROR("Invalid password ~p, login ~p", [PassWord, Login]),
                    {403, ?RESP_FAIL(<<"invalid password or login">>)}
            end;
        {ok, _, []} ->
            ?LOG_ERROR("Invalid login", []),
            {403, ?RESP_FAIL(<<"invalid password or login">>)}
    end.

-spec create_sid(binary(), Ts :: tuple()) -> error | binary().
create_sid(Login, DateEnd) ->
    Sid = generate_unique_sid(),
    DuplicatesList = ets:select(sids_cache, [{
        {'$1', '$2', '_', '_'},
        [{'=:=', '$2', Login}],
        ['$1']
    }]),
    Statement = case DuplicatesList of
             [] -> "insert_sid";
             [_SidDel] -> "update_sid"
         end,
    case {auth_hub_pg:insert(Statement, [Login, Sid, DateEnd]), DuplicatesList} of
        {{ok, 1}, []} ->
            RolesTab = auth_hub_pg:get_roles(Login),
            true = ets:insert(sids_cache, {Sid, Login, RolesTab, DateEnd}),
            Sid;
        {{ok, 1}, [SidDel]} ->
            true = ets:delete(sids_cache, SidDel),
            RolesTab = auth_hub_pg:get_roles(Login),
            true = ets:insert(sids_cache, {Sid, Login, RolesTab, DateEnd}),
            Sid;
        {{error, Reason}, _} ->
            ?LOG_ERROR("Db error, insert('insert_sid', [~p, ~p, ~p, ~p]), reason ~p", [Login, Sid, DateEnd, Reason]),
            error
    end.

-spec generate_unique_sid() -> binary().
generate_unique_sid() ->
    Sid = list_to_binary(uuid:to_string(simple, uuid:uuid1())),
    case ets:lookup(sids_cache, Sid) of
        [] ->
            Sid;
        _Other ->
            generate_unique_sid()
    end.


%% ========= check_sid =========

-spec handle_get(binary(), map()) -> term().
handle_get(<<"GET">>, Req) ->
    %SidAuth = cowboy_req:header(<<"sid">>, Req, undefined),
    {HttpCode, RespBodyMap} = handle_get_req(Req),
    RespBody = jsone:encode(RespBodyMap),
    cowboy_req:reply(HttpCode, #{<<"content-type">> => <<"application/json; charset=UTF-8">>}, RespBody, Req);
handle_get(Method, Req) ->
    ?LOG_ERROR("Method ~p not allowed ~p~n", [Method, Req]),
    cowboy_req:reply(405, Req).

-spec handle_get_req(map()) -> {integer(), map()}.
handle_get_req(#{qs := undefined}) ->
    ?LOG_ERROR("Api params is undefined", []),
    {422, ?RESP_FAIL(<<"absent needed params in uri">>)};
handle_get_req(#{qs := ParamsRow}) ->
    List = binary:split(ParamsRow, <<"&">>, [global]),
    case qs_to_proplist(List, []) of
        error ->
            {400, ?RESP_FAIL(<<"invalid params in uri">>)};
        OtherParams ->
            Sid = proplists:get_value(<<"sid">>, OtherParams, undefined),
            case auth_hub_tools:check_sid(Sid) of
                error ->
                    {400, ?RESP_FAIL(<<"invalid sid in uri">>)};
                legacy_sid ->
                    {200, ?RESP_SUCCESS_CHECK_SID(false)};
                {Sid, _Login, _RolesTab, _TsEnd} ->
                    {200, ?RESP_SUCCESS_CHECK_SID(true)}
            end
    end.

-spec qs_to_proplist(list(), list()) -> list().
qs_to_proplist([], Result) -> Result;
qs_to_proplist([H|T], Result) ->
    case binary:split(H, <<"=">>, [global]) of
        [Key, Value] ->
            qs_to_proplist(T, Result ++ [{Key, Value}]);
        Other ->
            ?LOG_ERROR("Invalid params in api ~p", [Other]),
            error
    end.

