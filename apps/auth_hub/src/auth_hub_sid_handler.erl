-module(auth_hub_sid_handler).
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
    {Status, RespMap} = handle_body(Body),
    RespBody = jsone:encode(RespMap),
    ?LOG_DEBUG("Post responce ~p, ~p", [Status, RespMap]),
    cowboy_req:reply(Status, #{<<"content-type">> => <<"application/json; charset=UTF-8">>}, RespBody, Req).

-spec handle_body(binary()) -> {integer(), map()}.
handle_body(Body) ->
    case jsone:try_decode(Body) of
        {error, Reason} ->
            ?LOG_ERROR("Decode error, ~p", [Reason]),
            {400, ?JSON_ERROR(<<"Invalid request format">>)};
        #{<<"login">> := Login, <<"pass">> := PassWord, <<"subsystem">> := SubSys} ->
            get_session(Login, PassWord, SubSys);
        _OtherMap ->
            ?LOG_ERROR("Absent needed params", []),
            {422, ?JSON_ERROR(<<"absent needed params">>)}
    end.

-spec get_session(binary(), binary(), binary()) -> {integer(), map()}.
get_session(Login, PassWord, SubSys) ->
    case auth_hub_pg:select("get_passhash", [Login]) of
        {error, Reason} ->
            ?LOG_ERROR("Db error ~p", [Reason]),
            {403, ?RESP_FAIL(<<"invalid password or login">>)};
        {ok, [{PermitHash}]} ->
            [{salt, Salt}] = ets:lookup(opts, salt),
            SaltBin = list_to_binary(Salt),
            PassHash = io_lib:format("~64.16.0b", [binary:decode_unsigned(crypto:hash(sha256, <<PassWord/binary, SaltBin/binary>>))]),
            case binary_to_list(PermitHash) =:= PassHash of
                true ->
                    Sid = create_sid(Login, PassWord, SubSys),
                    Ts = calendar:local_time(),
                    TsStart = auth_hub_converter:ts_to_bin(Ts),
                    TsSec = calendar:datetime_to_gregorian_seconds(Ts),
                    DateEnd = calendar:gregorian_seconds_to_datetime(TsSec + 1800),
                    TsEnd = auth_hub_converter:ts_to_bin(DateEnd),
                    {200, ?RESP_SUCCESS_SID(Sid, TsStart, TsEnd)};
                false ->
                    ?LOG_ERROR("Invalid password ~p, login ~p", [PassWord, Login]),
                    {403, ?RESP_FAIL(<<"invalid password or login">>)}
            end
    end.




create_sid(_Login, _PassWord, _SubSys) ->
    <<"d891c383998ed8568f885f5">>
    .