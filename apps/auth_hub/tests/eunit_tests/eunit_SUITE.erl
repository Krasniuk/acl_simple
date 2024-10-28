-module(eunit_SUITE).
-author('Mykhailo Krasniuk <mykhailo.krasniuk@privatbank.ua>').

-include_lit("common_test/include/ct.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, groups/0]).

-export([run_eunit_tests/1]).

%% ==================================
%% Export for Common Tests
%% ==================================

init_per_suite(Config) ->
  Config.

end_per_suite(Config) ->
  Config.

groups() ->
  [].

all() ->
  [run_eunit_tests].


%% =================================================
%% Cases
%% =================================================

run_eunit_tests(_Config) ->
  ok = eunit:test(auth_hub_test).

