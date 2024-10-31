-module(auth_hub_converter).
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').

-export([ts_to_bin/1]).


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