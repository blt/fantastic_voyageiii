-module(trimmed).

-export([start/0]).

child(Parent) ->
    Parent ! {child_alive, self()},
    receive
        ack ->
            ok
    end.

start() ->
    Self = self(),
    ChildPid = erlang:spawn(fun() -> child(Self) end),
    receive
        {child_alive, ChildPid} ->
            erlang:send(ChildPid, ack)
    end.
