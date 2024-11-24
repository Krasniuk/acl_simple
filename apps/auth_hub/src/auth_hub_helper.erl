-module(auth_hub_helper).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').

-export([ts_to_bin/1, check_sid/1, check_roles/2]).


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