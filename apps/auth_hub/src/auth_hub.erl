-module(auth_hub). %% Module for common tests
-author('Mykhailo Krasniuk <miha.190901@gmail.com>').

-export([start/0, stop/0]).


start() ->
    start(auth_hub).

stop() ->
    application:stop(auth_hub).


%% =====================================

start(AppName) ->
    F = fun({App, _, _}) -> App end,
    ok = load(AppName),
    {ok, Dependencies} = application:get_key(AppName, applications),
    [begin
         RunningApps = lists:map(F, application:which_applications()),
         case lists:member(A, RunningApps) of
             true ->
                 ok;
             false ->
                 ok = start(A)
         end
     end || A <- Dependencies],
    ok = application:start(AppName).

load(AppName) ->
    F = fun({App, _, _}) -> App end,
    LoadedApps = lists:map(F, application:loaded_applications()),
    case lists:member(AppName, LoadedApps) of
        true ->
            ok;
        false ->
            ok = application:load(AppName)
    end.

