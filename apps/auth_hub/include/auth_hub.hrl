-author('Mykhailo Krasniuk <miha.190901@gmail.com>').

-define(LOG_DEBUG(Format, Args),    lager:log(debug,    self(), Format, Args)).
-define(LOG_INFO(Format, Args),     lager:log(info,     self(), Format, Args)).
-define(LOG_WARNING(Format, Args),  lager:log(warning,  self(), Format, Args)).
-define(LOG_ERROR(Format, Args),    lager:log(error,    self(), Format, Args)).
-define(LOG_CRITICAL(Format, Args), lager:log(critical, self(), Format, Args)).


-define(JSON_ERROR(Req),                  #{<<"fail">> => #{<<"info">> => Req}}).
-define(JSON_OK,                          #{<<"success">> => #{<<"info">> => <<"ok">>}}).
-define(JSON_SHOW_ALLOW_ROLES(ListRoles), #{<<"success">> => #{<<"roles">> => ListRoles}}).
-define(JSON_USERS(Users),                #{<<"success">> => #{<<"users">> => Users}}).
-define(JSON_CUSTOM_GET_ROLES_OK(Roles),  #{<<"success">> => #{<<"roles">> => Roles}}).
-define(JSON_ROLES_OF_USER(UserName, Roles), #{<<"success">> => #{<<"user">> => UserName, <<"roles">> => Roles}}).
-define(JSON_DEVELOPMENT,                    #{<<"fail">> => #{<<"info">> => <<"develop now">>}}).

-define(RESP_SUCCESS_SID(Sid, TsStart, TsEnd), #{<<"success">> => #{<<"sid">> => Sid, <<"ts_start">> => TsStart, <<"ts_end">> => TsEnd}}).
-define(RESP_FAIL(Info), #{<<"fail">> => #{<<"info">> => Info}}).

-define(SQL_DELETE_SIDS, "DELETE FROM sids WHERE").