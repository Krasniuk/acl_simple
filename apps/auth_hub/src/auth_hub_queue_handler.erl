-module(auth_hub_queue_handler).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').

-include("auth_hub.hrl").

-export([init/2]).

init(Req, Opts) ->
    Method = cowboy_req:method(Req),
    HasBody = cowboy_req:has_body(Req),
    Resp = handle_post(Method, HasBody, Req),
    {ok, Resp, Opts}.

handle_post(<<"POST">>, true, Req) ->
    {ok, Body, _Req} = cowboy_req:read_body(Req),
  %  {Status, Json} = handle_body(Body),
  %  cowboy_req:reply(Status, #{<<"content-type">> => <<"application/json; charset=UTF-8">>}, Json, Req);
    cowboy_req:reply(200, #{<<"content-type">> => <<"application/json; charset=UTF-8">>}, jsone:encode(?JSON_DEVELOPMENT), Req);
handle_post(Method, _, Req) ->
    ?LOG_ERROR("405; Not used method: ~p", [Method]),
    cowboy_req:reply(405, Req).


