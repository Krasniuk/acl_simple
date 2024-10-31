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
        {ok, #{<<"login">> := Login, <<"pass">> := PassWord, <<"subsystem">> := SubSys}, _} ->
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
        {ok, _, [{PermitHash}]} ->
            [{salt, Salt}] = ets:lookup(opts, salt),
            SaltBin = list_to_binary(Salt),
            PassHash = io_lib:format("~64.16.0b", [binary:decode_unsigned(crypto:hash(sha256, <<PassWord/binary, SaltBin/binary>>))]),
            case binary_to_list(PermitHash) =:= PassHash of
                true ->
                    Ts = calendar:local_time(),
                    TsStart = auth_hub_converter:ts_to_bin(Ts),
                    TsSec = calendar:datetime_to_gregorian_seconds(Ts),
                    DateEnd = calendar:gregorian_seconds_to_datetime(TsSec + 1800),
                    TsEnd = auth_hub_converter:ts_to_bin(DateEnd),
                    case create_sid(Login, SubSys, DateEnd) of
                        subsystem_error ->
                            {400, ?RESP_FAIL(<<"invalid subsystem">>)};
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

-spec create_sid(binary(), binary(), Ts :: tuple()) -> error | binary().
create_sid(Login, SubSys, DateEnd) ->
    Sid = generate_unique_sid(),
    DuplicatesList = ets:select(sids_cache, [{
        {'$1', '$2', '$3', '_', '_'},
        [{'=:=', '$2', SubSys}, {'=:=', '$3', Login}],
        ['$1']
    }]),
    Statement = case DuplicatesList of
             [] -> "insert_sid";
             [_SidDel] -> "update_sid"
         end,
    case {auth_hub_pg:insert(Statement, [Login, SubSys, Sid, DateEnd]), DuplicatesList} of
        {{ok, 1}, []} ->
            true = ets:insert(sids_cache, {Sid, SubSys, Login, null, DateEnd}),
            Sid;
        {{ok, 1}, [SidDel]} ->
            true = ets:delete(sids_cache, SidDel),
            true = ets:insert(sids_cache, {Sid, SubSys, Login, null, DateEnd}),
            Sid;
        {{error, {_, _, _, foreign_key_violation, _, _}}, _} ->
            ?LOG_ERROR("Incorect subsystem", []),
            subsystem_error;
        {{error, Reason}, _} ->
            ?LOG_ERROR("Db error, insert('insert_sid', [~p, ~p, ~p, ~p]), reason ~p", [Login, SubSys, Sid, DateEnd, Reason]),
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

