-author('Mykhailo Krasniuk <miha.190901@gmail.com>').

-define(LOG_DEBUG(Format, Args),    lager:log(debug,    self(), Format, Args)).
-define(LOG_INFO(Format, Args),     lager:log(info,     self(), Format, Args)).
-define(LOG_WARNING(Format, Args),  lager:log(warning,  self(), Format, Args)).
-define(LOG_ERROR(Format, Args),    lager:log(error,    self(), Format, Args)).
-define(LOG_CRITICAL(Format, Args), lager:log(critical, self(), Format, Args)).


-define(SERVICE_SUBSYSTEM, <<"authHub">>).
-define(API_PERMIT_ROLES, #{
    {<<>>,                    <<"/allow/subsystems/roles/info">>} => [<<"am">>, <<"la">>, <<"si">>],
    {<<"create_roles">>,      <<"/allow/roles/change">>} =>          [<<"am">>, <<"la">>, <<"cr">>],
    {<<"delete_roles">>,      <<"/allow/roles/change">>} =>          [<<"am">>, <<"la">>, <<"dr">>],
    {<<"create_subsystems">>, <<"/allow/subsystems/change">>} =>     [<<"am">>],
    {<<"delete_subsystems">>, <<"/allow/subsystems/change">>} =>     [<<"am">>],

    {<<"create_users">>,      <<"/users">>} =>                       [<<"am">>, <<"la">>, <<"cu">>],
    {<<"delete_users">>,      <<"/users">>} =>                       [<<"am">>, <<"la">>, <<"du">>],
    {<<>>,                    <<"/users/info">>} =>                  [<<"am">>, <<"la">>, <<"si">>],

    {<<"add_roles">>,         <<"/roles/change">>} =>                [<<"am">>, <<"la">>, <<"ar">>],
    {<<"remove_roles">>,      <<"/roles/change">>} =>                [<<"am">>, <<"la">>, <<"rr">>]
}).

-define(RESP_SUCCESS_SID(Sid, TsStart, TsEnd), #{<<"success">> => #{<<"sid">> => Sid, <<"ts_start">> => TsStart, <<"ts_end">> => TsEnd}}).
-define(RESP_SUCCESS_CHECK_SID(Bool), #{<<"success">> => #{<<"is_active_session">> => Bool}}).
-define(RESP_SUCCESS(Info), #{<<"success">> => #{<<"info">> => Info}}).
-define(RESP_SUCCESS_ROLES(SubSys, RolesList), #{<<"success">> => #{<<"subsystem">> => SubSys, <<"roles">> => RolesList}}).
-define(RESP_SUCCESS_SPACES(SubSys, SpaceMap), #{<<"success">> => #{<<"subsystem">> => SubSys, <<"space_roles">> => SpaceMap}}).
-define(RESP_SUCCESS_LOGIN(Login), #{<<"success">> => #{<<"login">> => Login}}).
-define(RESP_FAIL_USERS(Login, Result), #{<<"login">> => Login, <<"saccess">> => false, <<"result">> => Result}).
-define(RESP_FAIL(Info), #{<<"fail">> => #{<<"info">> => Info}}).

-define(SQL_DELETE_SIDS, "DELETE FROM sids WHERE").
-define(SQL_DELETE_ROLES(Login, SubSys, Space), "DELETE FROM roles WHERE login='" ++ Login ++ "' and subsystem='" ++ SubSys ++ "' and space='" ++ Space ++ "' and (").
-define(SQL_INSERT_ROLES, "INSERT INTO roles (login, subsystem, role, space) values ").
-define(SQL_INIT_SIDS, "SELECT sid, login, null, ts_end FROM sids").
-define(SQL_INIT_SUBSYS, "SELECT subsystem FROM allow_subsystems").
