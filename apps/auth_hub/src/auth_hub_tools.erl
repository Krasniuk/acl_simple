-module(auth_hub_tools).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').

-export([ts_to_bin/1]).
-export([check_sid/1, check_roles/2]).
-export([validation/2, valid_login/1, valid_subsystems/1]).


-spec ts_to_bin(DateTs::tuple()) -> binary().
ts_to_bin({{Y, M, D}, {H, Mi, S}}) ->
    YBin = integer_to_binary(Y),
    [MBin, DBin, HBin, MiBin, SBin] = correct_row_date([M, D, H, Mi, round(S)]),
    <<YBin/binary, "-", MBin/binary, "-", DBin/binary, " ", HBin/binary, ":", MiBin/binary, ":", SBin/binary>>.

-spec correct_row_date(list()) -> list().
correct_row_date([]) -> [];
correct_row_date([Arg|Tail]) ->
    BinArg = integer_to_binary(Arg) ,
    case byte_size(BinArg) =:= 2 of
        false ->
            [<<"0", BinArg/binary>>| correct_row_date(Tail)];
        true ->
            [BinArg|correct_row_date (Tail)]
    end.

-spec check_sid(undefined | binary()) -> error | legacy_sid | {binary(), binary(), RolesTab::map(), tuple()}.
check_sid(undefined) ->
    error;
check_sid(Sid) when byte_size(Sid) == 32 ->
    case ets:lookup(sids_cache, Sid) of
        [] ->
            legacy_sid;
        [{Sid, Login, RolesTab, TsEnd}] ->
            TsNowSec = calendar:datetime_to_gregorian_seconds(calendar:local_time()),
            TsEndSec = calendar:datetime_to_gregorian_seconds(TsEnd),
            case TsEndSec - TsNowSec > 0 of
                false ->
                    legacy_sid;
                true ->
                    {Sid, Login, RolesTab, TsEnd}
            end
    end;
check_sid(_Sid) ->
    error.

-spec check_roles(LoginRoles::list(), PermitRoles::list()) -> true | false.
check_roles(_Roles, []) -> true;
check_roles([], _PermitRoles) -> false;
check_roles([Role|T], PermitRoles) ->
    case lists:member(Role, PermitRoles) of
        true ->
            true;
        false ->
            check_roles(T, PermitRoles)
    end.


-spec validation(atom(), tuple()) -> boolean().
validation(create_users, {Login, Pass}) when is_binary(Pass) and is_binary(Login) ->
    ValidLogin = valid_login(Login),
    ValidPass = {match, [{0, byte_size(Pass)}]} =:= re:run(Pass, "[a-zA-Z_\\d-#&$%]{8,100}", []),
    ValidPass and ValidLogin;
validation(change_roles, {Login, SubSys, Roles}) when is_binary(SubSys) and is_list(Roles) and is_binary(Login) ->
    ValidSubSys = ets:member(subsys_cache, SubSys),
    ValidRoles = valid_roles(Roles),
    ValidLogin = valid_login(Login),
    ValidSubSys and ValidLogin and ValidRoles;
validation(create_subsystems, {SubSys, Desc}) when is_binary(SubSys) and is_binary(Desc) ->
    VSubSys = {match, [{0, byte_size(SubSys)}]} =:= re:run(SubSys, "[a-zA-Z_\\d]{1,50}", []),
    VDesc = {match, [{0, byte_size(Desc)}]} =:= re:run(Desc, "[a-zA-Z-:=+,.()\/@#{}'' \\d]{0,100}", []),
    %?LOG_DEBUG("VSubSys = ~p, VDesc = ~p", [VSubSys, VDesc]),
    VSubSys and VDesc;
validation(create_roles, {SubSys, Role, Desc}) when is_binary(SubSys) and is_binary(Role) and is_binary(Desc) ->
    VSubSys = ets:member(subsys_cache, SubSys),
    VRole = {match, [{0, byte_size(Role)}]} =:= re:run(Role, "[a-z]{2}", []),
    VDesc = {match, [{0, byte_size(Desc)}]} =:= re:run(Desc, "[a-zA-Z-:=+,.()\/@#{}'' \\d]{0,100}", []),
    VSubSys and VRole and VDesc;
validation(_, _) ->
    false.

-spec valid_roles(list()) -> boolean().
valid_roles([]) -> true;
valid_roles([Role | T]) when is_binary(Role) ->
    case {match, [{0, byte_size(Role)}]} =:= re:run(Role, "[a-z]{2}", []) of
        true ->
            valid_roles(T);
        false ->
            false
    end;
valid_roles(_) ->
    false.

-spec valid_login(binary()) -> boolean().
valid_login(Login) when is_binary(Login) ->
    {match, [{0, byte_size(Login)}]} =:= re:run(Login, "[a-zA-Z][a-zA-Z_\\d]{2,50}", []);
valid_login(_Login) ->
    false.

-spec valid_subsystems(list()) -> boolean().
valid_subsystems([]) -> true;
valid_subsystems([SubSys | T]) when is_binary(SubSys) ->
    case ets:member(subsys_cache, SubSys) of
        true ->
            valid_subsystems(T);
        false ->
            false
    end;
valid_subsystems(_) ->
    false.