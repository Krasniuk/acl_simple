-module(admin_fail_SUITE).
-author('Mykhailo Krasniuk <mykhailo.krasniuk@privatbank.ua>').

-include("../include/test.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, groups/0]).

-export([missing_body/1, bad_http_method/1, parse_body_fail/1, add_allow_roles/1]).


%% ==================================
%% Export for Common Tests
%% ==================================

init_per_suite(Config) ->
  %  ok = application:set_env(?START_ENV),
 %   ok = auth_hub:start(),
    Config.

groups() ->
    [].

end_per_suite(Config) ->
    ok = auth_hub:stop(),
    Config.


all() ->
    [
        missing_body,
        bad_http_method,
        parse_body_fail,
        add_allow_roles
    ].


%% =================================================
%% Cases
%% =================================================

missing_body(_Config) ->
    {ok, {{_, 400, _}, _Headers, RespBody}} = httpc:request(post, {?URL_ADMIN, ?HEADERS, "application/json;charset=UTF-8", ""},
        [{timeout, 4000}], [{body_format, binary}]),
    ok = ct:pal("RespBody = ~p", [RespBody]),
    <<"Missing body.">> = RespBody.

bad_http_method(_Config) ->
    {ok, {{_, 405, _}, _Headers, []}} = httpc:request(get, {?URL_ADMIN, []}, [{timeout, 4000}], []).

parse_body_fail(_Config) ->
    ReqBody = "{\"parameters\":{\"method\":\"show_allow_roles\"",
    {ok, {{_, 206, _}, _Headers, RespBody}} = httpc:request(post, {?URL_ADMIN, ?HEADERS, "application/json;charset=UTF-8", ReqBody},
        [{timeout, 4000}], [{body_format, binary}]),
    ok = ct:pal("RespBody = ~p", [RespBody]),
    #{<<"fail">> := <<"Invalid request format">>} = jsone:decode(RespBody).

add_allow_roles(_Config) ->
    #{<<"fail">> := <<"Invalid request format">>} = request(add_allow_roles, {[<<"1a">>]}),
    #{<<"fail">> := <<"Invalid request format">>} = request(add_allow_roles, {[<<"_a">>]}),
    #{<<"fail">> := <<"Invalid request format">>} = request(add_allow_roles, {[<<"am./">>]}),
    #{<<"fail">> := <<"Invalid request format">>} = request(add_allow_roles, {[<<"am ">>]}),
    #{<<"fail">> := <<"Invalid request format">>} = request(add_allow_roles, {[<<"r1913">>, <<"w1913">>, <<"am ">>]}).


% -----------------------------------

-spec request(atom(), tuple()) -> ok | list().
request(add_allow_roles, {Roles}) ->
    Body = #{<<"auth">> => #{<<"login">> => <<"admin">>, <<"passhash">> => binary_to_list(crypto:hash(sha, <<"1234">>))},
        <<"parameters">> => #{<<"method">> => <<"add_allow_roles">>, <<"roles">> => Roles}},
    ReqBody = jsone:encode(Body),
    {ok, {_, _, RespBody}} = httpc:request(post, {?URL_ADMIN, ?HEADERS, "application/json;charset=UTF-8", ReqBody},
        [{timeout, 4000}], [{body_format, binary}]),
    ok = ct:pal("show_allow_roles ~n RespBody = ~p", [RespBody]),
    jsone:decode(RespBody);
request(delete_allow_roles, {Roles}) ->
    Body = #{<<"auth">> => #{<<"login">> => <<"admin">>, <<"passhash">> => binary_to_list(crypto:hash(sha, <<"1234">>))},
        <<"parameters">> => #{<<"method">> => <<"delete_allow_roles">>, <<"roles">> => Roles}},
    ReqBody = jsone:encode(Body),
    {ok, {_, _, RespBody}} = httpc:request(post, {?URL_ADMIN, ?HEADERS, "application/json;charset=UTF-8", ReqBody},
        [{timeout, 4000}], [{body_format, binary}]),
    ok = ct:pal("show_allow_roles ~n RespBody = ~p", [RespBody]),
    #{<<"result">> := <<"ok">>} = jsone:decode(RespBody),
    ok;

request(user_add, {User, PassHash}) ->
    Body = #{<<"auth">> => #{<<"login">> => <<"admin">>,
        <<"passhash">> => binary_to_list(crypto:hash(sha, <<"1234">>))},
        <<"parameters">> => #{<<"method">> => <<"user_add">>,
            <<"user">> => User,
            <<"passhash">> => PassHash}},
    ReqBody = jsone:encode(Body),
    {ok, {_, _, RespBody}} = httpc:request(post, {?URL_ADMIN, ?HEADERS, "application/json;charset=UTF-8", ReqBody},
        [{timeout, 4000}], [{body_format, binary}]),
    ok = ct:pal("user_add ~p ~n RespBody = ~p", [User, RespBody]),
    #{<<"result">> := <<"ok">>} = jsone:decode(RespBody),
    ok;
request(user_delete, {User}) ->
    Body = #{<<"auth">> => #{<<"login">> => <<"admin">>,
        <<"passhash">> => binary_to_list(crypto:hash(sha, <<"1234">>))},
        <<"parameters">> => #{<<"method">> => <<"user_delete">>,
            <<"user">> => User}},
    ReqBody = jsone:encode(Body),
    {ok, {_, _, RespBody}} = httpc:request(post, {?URL_ADMIN, ?HEADERS, "application/json;charset=UTF-8", ReqBody},
        [{timeout, 4000}], [{body_format, binary}]),
    ok = ct:pal("user_delete ~p ~n RespBody = ~p", [User, RespBody]),
    #{<<"result">> := <<"ok">>} = jsone:decode(RespBody),
    ok;
request(show_all_users, {}) ->
    Body = #{<<"auth">> => #{<<"login">> => <<"admin">>,
        <<"passhash">> => binary_to_list(crypto:hash(sha, <<"1234">>))},
        <<"parameters">> => #{<<"method">> => <<"show_all_users">>}},
    ReqBody = jsone:encode(Body),
    {ok, {_, _, RespBody}} = httpc:request(post, {?URL_ADMIN, ?HEADERS, "application/json;charset=UTF-8", ReqBody},
        [{timeout, 4000}], [{body_format, binary}]),
    ok = ct:pal("show_all_users ~n RespBody = ~p", [RespBody]),
    #{<<"result">> := <<"ok">>,
        <<"users">> := ListUsers} = jsone:decode(RespBody),
    ListUsers;

request(show_roles, {User}) ->
    Body = #{<<"auth">> => #{<<"login">> => <<"admin">>, <<"passhash">> => binary_to_list(crypto:hash(sha, <<"1234">>))},
        <<"parameters">> => #{<<"method">> => <<"show_roles">>, <<"user">> => User}},
    ReqBody = jsone:encode(Body),
    {ok, {_, _, RespBody}} = httpc:request(post, {?URL_ADMIN, ?HEADERS, "application/json;charset=UTF-8", ReqBody},
        [{timeout, 4000}], [{body_format, binary}]),
    ok = ct:pal("show_roles ~p ~n RespBody = ~p", [User, RespBody]),
    #{<<"result">> := <<"ok">>,
        <<"user">> := User,
        <<"roles">> := ListRoles} = jsone:decode(RespBody),
    ListRoles;
request(roles_add, {User, Roles}) ->
    Body = #{<<"auth">> => #{<<"login">> => <<"admin">>,
        <<"passhash">> => binary_to_list(crypto:hash(sha, <<"1234">>))},
        <<"parameters">> => #{<<"method">> => <<"roles_add">>,
            <<"user">> => User,
            <<"roles">> => Roles}},
    ReqBody = jsone:encode(Body),
    {ok, {_, _, RespBody}} = httpc:request(post, {?URL_ADMIN, ?HEADERS, "application/json;charset=UTF-8", ReqBody},
        [{timeout, 4000}], [{body_format, binary}]),
    ok = ct:pal("roles_add ~p ~n RespBody = ~p", [{User, Roles}, RespBody]),
    #{<<"result">> := <<"ok">>} = jsone:decode(RespBody),
    ok;
request(roles_delete, {User, Roles}) ->
    Body = #{<<"auth">> => #{<<"login">> => <<"admin">>,
        <<"passhash">> => binary_to_list(crypto:hash(sha, <<"1234">>))},
        <<"parameters">> => #{<<"method">> => <<"roles_delete">>,
            <<"user">> => User,
            <<"roles">> => Roles}},
    ReqBody = jsone:encode(Body),
    {ok, {_, _, RespBody}} = httpc:request(post, {?URL_ADMIN, ?HEADERS, "application/json;charset=UTF-8", ReqBody},
        [{timeout, 4000}], [{body_format, binary}]),
    ok = ct:pal("roles_delete ~p ~n RespBody = ~p", [{User, Roles}, RespBody]),
    #{<<"result">> := <<"ok">>} = jsone:decode(RespBody),
    ok.
