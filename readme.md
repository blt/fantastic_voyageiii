# Fantastic Voyage III: Destination BEAM

## Timing

20 minute slot, 5 minute questions

## Abstract

In 2017 I gave a keynote titled "Piecemeal Into Space: Reliability, Safety and
Erlang Principles". In that talk I discussed the high-level semantic model of
Erlang, a slightly more concrete abstract representation of processes and their
interaction with the schedulers and extrapolated this out into application to
spacecraft systems. In this talk we'll go deeper, discussing the concrete
implementation of core Erlang concepts as reflected in the BEAM: the message
process queue, the layout of a process and the structure the BEAM uses to
associate names and PIDs.

## Actual Talk Structure

Have a supervised process that runs through some simple protocol, maybe

 * one process which holds an ETS table
   * ETS table is table of counters
 * N processes which send some term to be summed up
 * 1 process which queryes the table holder for counts

Show:

  * the relationship of gen_server, gen_supervisor, gen
  * how name registration / lookups happens
  * interior of message queue
  * interior of ETS

## Additional Reading

* https://github.com/happi/theBeamBook
* http://rvirding.blogspot.com/2009/10/what-are-bifs.html
* http://www.erlang-factory.com/static/upload/media/1427794436907373porting.pdf
* http://blog.erlang.org/Interpreter-Optimizations/

## Location of Things

### lib/stdlib/src

Here you'll find the `gen_*` implementations. Note that a `gen_supervisor` is a
`gen_server`. `gen_server` is a `gen`.

ETS: lib/stdlib/src/ets.erl <-- erl shell
     erts/emulator/beam/erl_db.c <-- bif

## What is a process?

Defined in erl_process.h: `Process`

    typedef struct process Process;

Struct defn. starts line 929. The heap/stack are per-process, 939 to 947.

`LINK_MESSAGE` in erl_message.h 371 adds a message onto the `sig_inq`, of type `ErtsSignalInQueue`.

`erl_message.c` 319 has `queue_messages`.

What are the different locks available for a process? The process does not have
a global lock, it has _field_ locks. These are defined in `erl_process_lock.h`,
starting 108. `ErtsProcLocks` -> `erts_aint32_t` -> `ethr_sint32_t` ->
`long|int`. Each lock is 1 shifted some distance to the left. Starting at 207
there are combinations of locks, explaining the shift approach.

`erts_mbuf_size` is a valuable indicator of what comprises the message buffer as
it's split between multiple things.

NOTE need to establish relationship of `queue_messages` and `erts_send_message`.

See `remove_message` in `msg_instrs.tab`. Unsure what '.tab' means.

BEAM instructions are given in '.tab' files. You can see the whole list in
`emulator/Makefile.in` line 35, `OPCODE_TABLES`

send is defined in `preloaded/src/erlang.erl` at 2365, nif. Bounces to
`ebif_bang_2` which is in `bif.c` at 1780 which is `erl_send` in same file on
2232. Key here is `do_send`, 1861.

This `do_send` has the key to lookup. Starts 1894 when send target is an
atom. `erts_whereis_name_to_id` in `register.c` on 264. `erts_register_name` is
on 170. Both are operations on a hash table, defined in `hash.c`. Standard
bucket construction. `erts_register_name` looks to require a rwlock -- TODO what
kind, `erts_rwmtx_rwunlock(&regtab_rwmtxt)` but where is the lock (ah, SMP
assumed the main lock [??? what is] has already been locked) -- but reading only
requires a read lock.

`regtab_rwmtxt` is an `ethr_mutex`. Real interesting bit of code,
`ethr_mutex`. 141 is the base, there's a bunch of different flags but the main
show is at 312 in `ethr_mutex.h`. Varaint type -- `normal`, `frequent_read`,
`extremely_frequent_read`. Fun. How does locking work? `erts_rwmtx_rwlock` is
`erts_rwmtx_rwlock_x` which is IFDEF'd to hell in `erl_threads.h` starting 1986

## Talk

Okay, start with smpl. That's three files:

* `smpl_sup` -- `supervisor`
* `smpl_snd` -- `gen_server`
* `smpl_rcv` -- `gen_server`

The gen_supervisor is defined here: lib/stdlib/src/supervisor.erl

`supervisor` is itself a `gen_server`. gen_server is defined here: `lib/stdlib/src/gen_server.erl`

NOTE

Inside `gen_server` I want to explore how a synchronous `gen_server:call` is done. That's:

```
call(Name, Request) ->
    case catch gen:call(Name, '$gen_call', Request) of
	{ok,Res} ->
	    Res;
	{'EXIT',Reason} ->
	    exit({Reason, {?MODULE, call, [Name, Request]}})
    end.
```

`gen_server` is defined in terms of `gen`. `gen` is defined here: `lib/stdlib/src/gen.erl`

```
call(Process, Label, Request) ->
    call(Process, Label, Request, ?default_timeout).

%% Optimize a common case.
call(Process, Label, Request, Timeout) when is_pid(Process),
  Timeout =:= infinity orelse is_integer(Timeout) andalso Timeout >= 0 ->
    do_call(Process, Label, Request, Timeout);
call(Process, Label, Request, Timeout)
  when Timeout =:= infinity; is_integer(Timeout), Timeout >= 0 ->
    Fun = fun(Pid) -> do_call(Pid, Label, Request, Timeout) end,
    do_for_proc(Process, Fun).

do_call(Process, Label, Request, Timeout) when is_atom(Process) =:= false ->
    Mref = erlang:monitor(process, Process),

    %% OTP-21:
    %% Auto-connect is asynchronous. But we still use 'noconnect' to make sure
    %% we send on the monitored connection, and not trigger a new auto-connect.
    %%
    erlang:send(Process, {Label, {self(), Mref}, Request}, [noconnect]),

    receive
        {Mref, Reply} ->
            erlang:demonitor(Mref, [flush]),
            {ok, Reply};
        {'DOWN', Mref, _, _, noconnection} ->
            Node = get_node(Process),
            exit({nodedown, Node});
        {'DOWN', Mref, _, _, Reason} ->
            exit(Reason)
    after Timeout ->
            erlang:demonitor(Mref, [flush]),
            exit(timeout)
    end.
```

Key area of interest is do_call. The handling code is back up in `gen_server`
though in `handle_msg`:

```
handle_msg({'$gen_call', From, Msg}, Parent, Name, State, Mod, HibernateAfterTimeout) ->
    Result = try_handle_call(Mod, Msg, From, State),
    case Result of
	{ok, {reply, Reply, NState}} ->
	    reply(From, Reply),
	    loop(Parent, Name, NState, Mod, infinity, HibernateAfterTimeout, []);
	{ok, {reply, Reply, NState, Time1}} ->
	    reply(From, Reply),
	    loop(Parent, Name, NState, Mod, Time1, HibernateAfterTimeout, []);
	{ok, {noreply, NState}} ->
	    loop(Parent, Name, NState, Mod, infinity, HibernateAfterTimeout, []);
	{ok, {noreply, NState, Time1}} ->
	    loop(Parent, Name, NState, Mod, Time1, HibernateAfterTimeout, []);
	{ok, {stop, Reason, Reply, NState}} ->
	    try
		terminate(Reason, ?STACKTRACE(), Name, From, Msg, Mod, NState, [])
	    after
		reply(From, Reply)
	    end;
	Other -> handle_common_reply(Other, Parent, Name, From, Msg, Mod, HibernateAfterTimeout, State)
    end;
handle_msg(Msg, Parent, Name, State, Mod, HibernateAfterTimeout) ->
    Reply = try_dispatch(Msg, Mod, State),
    handle_common_reply(Reply, Parent, Name, undefined, Msg, Mod, HibernateAfterTimeout, State).
```

The `reply/2` is just

```
%% -----------------------------------------------------------------
%% Send a reply to the client.
%% -----------------------------------------------------------------
reply({To, Tag}, Reply) ->
    catch To ! {Tag, Reply}.
```

The `From` of the reply is `{To, Tag}` and `Tag` is an `MRef`. The callers knows
that the reply has ogne round-trip because the monitoring ref is unique and has
come back again, either directly from the process the message was originally
sent to or some blessed helper. The use of the monitoring ref has the added
benefit of allowing the sync caller to know if the target has failed.

Okay. What is `gen_server`y about supervisor? The supervisor is all state about
its children, how to restart them. Lots of internal sets. The `start_child`
logic is:

```
handle_call({start_child, EArgs}, _From, State) when ?is_simple(State) ->
    Child = get_dynamic_child(State),
    #child{mfargs = {M, F, A}} = Child,
    Args = A ++ EArgs,
    case do_start_child_i(M, F, Args) of
	{ok, undefined} ->
	    {reply, {ok, undefined}, State};
	{ok, Pid} ->
	    NState = dyn_store(Pid, Args, State),
	    {reply, {ok, Pid}, NState};
	{ok, Pid, Extra} ->
	    NState = dyn_store(Pid, Args, State),
	    {reply, {ok, Pid, Extra}, NState};
	What ->
	    {reply, What, State}
    end;

handle_call({start_child, ChildSpec}, _From, State) ->
    case check_childspec(ChildSpec) of
	{ok, Child} ->
	    {Resp, NState} = handle_start_child(Child, State),
	    {reply, Resp, NState};
	What ->
	    {reply, {error, What}, State}
    end;
```

The external API `gen_server:call`'s its implementation. The actual details of
the State are kind of complicated and maybe not so interesting.

Now, two questions. How does 1. `erlang:send` work and 2. what's it take to look
up a name?

Okay, `erlc +to_core trimmed.erl` `child/1`

```
child(Parent) ->
    Parent ! {child_alive, self()},
    receive
        ack ->
            ok
    end.
```

becomes

```
'child'/1 =
    %% Line 5
    fun (_0) ->
	let <_1> =
	    call %% Line 6
		 'erlang':%% Line 6
			  'self'
		()
	in  do  %% Line 6
		call 'erlang':'!'
		    (_0, {'child_alive',_1})
		%% Line 7
		receive
		  %% Line 8
		  <'ack'> when 'true' ->
		      %% Line 9
		      'ok'
		after 'infinity' ->
		  'true'
```

The call to `erlang:send` in `start/0` is transformed into

```
			  call 'erlang':'send'
			      (ChildPid, 'ack')
```

Is there a difference between `!` and `erlang:send`? Well, if you search the
codebase you can find in `erts/preloaded/src/erlang.erl` that `erlang:send` is
defined as follows:

```
send(_Dest,_Msg,_Options) ->
    erlang:nif_error(undefined).
```

It's a BIF. Where's the BIF table? Turns out there's a script called
`erts/emulator/utils/make_tables` which I found by noticing a thing called
`bif_export` was referenced in `beam_bif_load.c`, which I guessed was related to
loading BIFs. I then grepped my way to `extern Export* bif_export[];` on line
234 of `make_tables`. This is called in `erts/emulator/Makefile.in` and is
passed, in part, a file called `beam/bif.tab`. There's a comment at the top which says:

```
# <bif-decl> ::= "bif" <bif> <C-name>* |
#                "ubif" <bif> <C-name>* |
#                "gcbif" <bif> <C-name>*
# <bif> ::= <module> ":" <name> "/" <arity>
```

Heyo, look at this on line 313:

```
bif erlang:'!'/2		ebif_bang_2
bif erlang:send/2
bif erlang:send/3
```

Turns out `!` and `erlang:send/2` and `erlang:send/3` all map to the same
thing. The `ebif_bang_2` is defined in `erts/emulator/beam/bif.c:1781`:

```
BIF_RETTYPE
ebif_bang_2(BIF_ALIST_2)
{
    return erl_send(BIF_P, BIF_ARG_1, BIF_ARG_2);
}
```

All those args are defines:

```
#define BIF_P A__p

#define BIF_ALIST Process* A__p, Eterm* BIF__ARGS, BeamInstr *A__I
#define BIF_CALL_ARGS A__p, BIF__ARGS, A__I

#define BIF_ALIST_0 BIF_ALIST
#define BIF_ALIST_1 BIF_ALIST
#define BIF_ALIST_2 BIF_ALIST
#define BIF_ALIST_3 BIF_ALIST
#define BIF_ALIST_4 BIF_ALIST

#define BIF_ARG_1  (BIF__ARGS[0])
#define BIF_ARG_2  (BIF__ARGS[1])
#define BIF_ARG_3  (BIF__ARGS[2])
#define BIF_ARG_4  (BIF__ARGS[3])
```

So, there's some C function called `erl_send` which gets a pointer to the
process doing the sending and the args to send. I'm actually confused about how
`send/3` is supported. Anyway, `erl_send`. It's defined in
`erts/emulator/beam/bif.c:2232` and calls a thing called `do_send`:

```
Eterm erl_send(Process *p, Eterm to, Eterm msg)
{
    Eterm retval;
    Eterm ref;
    Sint result;
    DeclareTypedTmpHeap(ErtsSendContext, ctx, p);
    ERTS_MSACC_PUSH_AND_SET_STATE_M_X(ERTS_MSACC_STATE_SEND);
    UseTmpHeap(sizeof(ErtsSendContext)/sizeof(Eterm), p);
#ifdef DEBUG
    ref = NIL;
#endif
    ctx->suspend = !0;
    ctx->connect = !0;
    ctx->deref_dep = 0;
    ctx->return_term = msg;
    ctx->dss.reds = (Sint) (ERTS_BIF_REDS_LEFT(p) * TERM_TO_BINARY_LOOP_FACTOR);
    ctx->dss.phase = ERTS_DSIG_SEND_PHASE_INIT;

    result = do_send(p, to, msg, &ref, ctx);

```

The rest of the function deals with the handling of `result`. What's `do_send`?
It's in `bif.c` as well at line 1861. It is, in no small part, a big if-else
tree:

```
static Sint
do_send(Process *p, Eterm to, Eterm msg, Eterm *refp, ErtsSendContext *ctx)
{
    Eterm portid;
    Port *pt;
    Process* rp;
    DistEntry *dep;
    Eterm* tp;

    if (is_internal_pid(to)) {
```

over:

* `is_internal_pid`
* `is_external_pid`
* `is_atom`
* `is_external_port`
* `is_internal_port`
* `is_tuple`

If you dig into these functions you'll find that they inspect tags in the
`Eterm`, the general term for any erlangy thing. Here's `Eterm` in
`erl_interface.h:288`:

```
typedef struct _eterm {
  union {
    Erl_Integer    ival;
    Erl_Uinteger   uival;
    Erl_LLInteger  llval;
    Erl_ULLInteger ullval;
    Erl_Float      fval;
    Erl_Atom       aval;
    Erl_Pid        pidval;
    Erl_Port       portval;
    Erl_Ref        refval;
    Erl_List       lval;
    Erl_EmptyList  nval;
    Erl_Tuple      tval;
    Erl_Binary     bval;
    Erl_Variable   vval;
    Erl_Function   funcval;
    Erl_Big        bigval;
  } uval;
} ETERM;
```

Big old union. Back in `do_send` the if/else branches are all working to turn
the `to` term into a process. For instance:

```
    if (is_internal_pid(to)) {
	if (IS_TRACED_FL(p, F_TRACE_SEND))
	    trace_send(p, to, msg);
	if (ERTS_PROC_GET_SAVED_CALLS_BUF(p))
	    save_calls(p, &exp_send);

	rp = erts_proc_lookup_raw(to);
	if (!rp)
	    return 0;
```

If we jump to `erts/emulator/beam/erl_process_lock.h:1084` then we see:

```
ERTS_GLB_INLINE Process *erts_proc_lookup_raw(Eterm pid)
{
    Process *proc;

    ERTS_LC_ASSERT(erts_thr_progress_lc_is_delaying());

    if (is_not_internal_pid(pid))
	return NULL;

    proc = (Process *) erts_ptab_pix2intptr_ddrb(&erts_proc,
						 internal_pid_index(pid));
    if (proc && proc->common.id != pid)
	return NULL;
    return proc;
}
```

This does an atomic read -- via `erts_ptab_pix2intptr_ddrb` of the offset in the
internal PID table. We won't get into the way atomics function in BEAM because
this is a short talk but I promise you should dig into it yourself. Build a TAGS
database and keep jumping around. Jumping down to the bottom of `do_send` we get:

```
 send_message: {
	ErtsProcLocks rp_locks = 0;
	if (p == rp)
	    rp_locks |= ERTS_PROC_LOCK_MAIN;
	/* send to local process */
	erts_send_message(p, rp, &rp_locks, msg);
	erts_proc_unlock(rp,
			     p == rp
			     ? (rp_locks & ~ERTS_PROC_LOCK_MAIN)
			     : rp_locks);
	return 0;
    }
}
```

Heyo, locking. `ERTS_PROC_LOCK_MAIN` seems important. What is that?

```
/*
 * Main lock:
 *   The main lock is held by the scheduler running a process. It
 *   is used to protect all fields in the process structure except
 *   for those fields protected by other process locks (follows).
 */
#define ERTS_PROC_LOCK_MAIN		(((ErtsProcLocks) 1) << 0)
```

via `erl_process_lock.h:110`. `ErtsProcLocks` is an `erts_aint32_t` or an atomic
32-bit integer. If the send is a self-send then the `rp_locks` is OREq'd with
`ERTS_PROC_LOCK_MAIN` becasue the scheduler -- which is an OS thread, recall --
already holds the lock is needs _because_ the processes `p` is being
executed. If we jump to `erl_message.c:595` to look at `erts_send_message` we'll
find, well, quite a lot. Here we get into the definition of processes, `sender`
and `receiver` are both pointers to such at the top of the function. Where is
this defined?

`erts/emulator/beam/erl_process.h:40` has a process as

```
typedef struct process Process;
```

The actual defn. starts much later in the file. Digging around in large C
projects like this can get intimidating, especially if the terminology that
you're familiar as a user is not reflected in the jargon of the source
code. BEAM feels like that sometimes. What is this line in `erl_message.c`

```
    receiver_state = erts_atomic32_read_nob(&receiver->state);
```

Up to? An atomic read is being done on a variable stuffed inside `struct
process`, defined as

> /* Process state flags (see ERTS_PSFLG_*) */

True to its name, it denotes the state of the process, passed into allocation of
the in-flight message on the receiver's heap -- via
`erts_alloc_message_heap_state`. The main concern of this function is to be sure
that `ERTS_PSFLG_OFF_HEAP_MSGQ` is not set, or to take a distinct action if it
is. Off heap message queue skips the main lock of the process but is more
expensive to allocate compared to on-heap messages which -- via
`erts_try_alloc_message_on_heap` -- does a lot of fiddly checking to decided
where to allocate new messages in the receiver's memory. There's an impressive
little state machine here and I warmly suggest you read it.

Okay! Once a message is copied to the receiver -- whether on-heap with the
cooperation of other processes or off-heap without them -- the final act of
`erts_send_message` is to call `erts_queue_proc_message`. Defined in
`erl_message.c` at line 440 this function does some more lock work, checks that
the process is not exiting before it does said lock work and sends an enqueue
signal. Note this means that a process might have a message copies into its
receiver but then be scheduled out before signaling, meaning that, under heavy
contention, there may be an appreciable delay before memory is allocation inside
the receiver process and the receiver process is aware of this. Caveats apply.

```
/**
 * @brief Send one message from a local process.
 *
 * It is up to the caller of this function to set the
 * correct seq_trace. The general rule of thumb is that
 * it should be set to am_undefined if the message
 * cannot be traced using seq_trace, if it can be
 * traced it should be set to the trace token. It should
 * very rarely be explicitly set to NIL!
 */
void
erts_queue_proc_message(Process* sender,
                        Process* receiver, ErtsProcLocks receiver_locks,
                        ErtsMessage* mp, Eterm msg)
{
    ERL_MESSAGE_TERM(mp) = msg;
    ERL_MESSAGE_FROM(mp) = sender->common.id;
    queue_messages(receiver, receiver_locks,
                   prepend_pending_sig_maybe(sender, receiver, mp),
                   &mp->next, 1);
}
```

Let's look into `queue_messages`. Defined in the same file -- `erl_message.c`
the preamble of the function deals with locking, debugging details. The
interesting bits are:

```
    if (!(receiver_locks & ERTS_PROC_LOCK_MSGQ)) {
        erts_proc_lock(receiver, ERTS_PROC_LOCK_MSGQ);
	locked_msgq = 1;
    }
```

Queueing a message requires holding the lock for the receiver's message queue --
makes sense -- and subsequent queue operations assume this lock is held. After
checking the receiver state, no point doing the work if the receiver is shutting
down, this happens:

```
    if (last == &first->next) {
        ASSERT(len == 1);
        LINK_MESSAGE(receiver, first);
    }
    else {
        erts_enqueue_signals(receiver, first, last, NULL, len, state);
    }
```

The queue is a linked list and so the check of where in the queue you are should
be familiar. Let's dig into `LINK_MESSAGE`, defined in `erl_message.h:371`:

```
/* Add one message last in message queue */
#define LINK_MESSAGE(p, msg) \
    do {                                                                \
        ASSERT(ERTS_SIG_IS_MSG(msg));                                   \
        ERTS_HDBG_CHECK_SIGNAL_IN_QUEUE__((p), "before");               \
        *(p)->sig_inq.last = (msg);                                     \
        (p)->sig_inq.last = &(msg)->next;                               \
        (p)->sig_inq.len++;                                             \
        ERTS_HDBG_CHECK_SIGNAL_IN_QUEUE__((p), "before");               \
    } while(0)
```

Drops the message at the back. Cool. What about `erts_enqueue_signals`?

```
erts_aint32_t erts_enqueue_signals(Process *rp, ErtsMessage *first,
                                   ErtsMessage **last, ErtsMessage **last_next,
                                   Uint num_msgs,
                                   erts_aint32_t in_state)
{
    return enqueue_signals(rp, first, last, last_next, num_msgs, in_state);
}
```

in `erl_proc_sig_queue.c` to `enqueue_signals` which adds the message to
something called `sig_inq` in the process. TBH I'm not totally sure what the
distinctions here are. Both paths manipulate the same queue but there's some
distinction here. Ah! It's described in `erl_message.h` line 238. There's an
'inner' and 'middle' queue. Middle queued messages are 'in transit' and don't
live in the process memory yet, stalling the sender but allowing the receiver to
complete the receipt if needed. Fancy.

Okay, that's `send/2,3` and `!`. What about receive? If you look in the BIF tab
you'll find it missing. Check out `msg_instrs.tab`:

```
// /*
//  * Skeleton for receive statement:
//  *
//  *             recv_mark L1                     Optional
//  *             call make_ref/monitor            Optional
//  *             ...
//  *             recv_set L1                      Optional
//  *      L1:          <-------------------+
//  *                   <-----------+       |
//  *                               |       |
//  *             loop_rec L2 ------+---+   |
//  *             ...               |   |   |
//  *             remove_message    |   |   |
//  *             jump L3           |   |   |
//  *		...                 |   |   |
//  *		loop_rec_end L1   --+   |   |
//  *      L2:          <---------------+   |
//  *	   	wait L1  -------------------+      or wait_timeout
//  *		timeout
//  *
//  *	 L3:    Code after receive...
//  *
//  */
```

Because there are many variaties of receives -- whether they match or not,
whether there's a timeout -- there's no one receive instruction but a host of
related things. Exactly what gets emitted is up to the optimizer, if I
understand correctly. Let's dig into `remove_message`:

```
    UNLINK_MESSAGE(c_p, msgp);
    JOIN_MESSAGE(c_p);
    CANCEL_TIMER(c_p);
```

The impl of `UNLINK_MESSAGE` is:

```
/* Unlink current message */
#define UNLINK_MESSAGE(p,msgp)                                          \
    do {                                                                \
        ErtsMessage *mp__ = (msgp)->next;                               \
        ERTS_HDBG_CHECK_SIGNAL_PRIV_QUEUE__((p), 0, "before");          \
        *(p)->sig_qs.save = mp__;                                       \
        (p)->sig_qs.len--;                                              \
        if (mp__ == NULL)                                               \
            (p)->sig_qs.last = (p)->sig_qs.save;                        \
        ERTS_HDBG_CHECK_SIGNAL_PRIV_QUEUE__((p), 0, "after");           \
    } while(0)
```

Here `p` is a `Process` and `msgp` is the 'current' message of the
queue. Unlinking a message adjust the queue size, sets the 'current' to the next
spot on the queue. Standard linked list. `JOIN_MESSAGE`:

```
/*
 * Reset message save point (after receive match).
 * Also invalidate the saved position since it may no
 * longer be safe to use.
 */
#define JOIN_MESSAGE(p)                                                 \
   do {                                                                 \
       (p)->sig_qs.save = &(p)->sig_qs.first;                           \
       ERTS_RECV_MARK_CLEAR((p));                                       \
   } while(0)
```

Now, lastly, how do you find a process name? What's the deal with all of
that. Let's jump back to `do_send` in `bif.c`, specifically this:

```
    } else if (is_atom(to)) {
	Eterm id = erts_whereis_name_to_id(p, to);

	rp = erts_proc_lookup_raw(id);
```

Recall that `do_send` is a big if tree based on the nature of the `to`, the
receiver of the message. The main show here is `erts_whereis_name_to_id`,
defined in `register.c:264`.

```
Eterm
erts_whereis_name_to_id(Process *c_p, Eterm name)
{
    Eterm res = am_undefined;
    HashValue hval;
    int ix;
    HashBucket* b;
    ErtsProcLocks c_p_locks = 0;
    if (c_p) {
        c_p_locks = ERTS_PROC_LOCK_MAIN;
        ERTS_CHK_HAVE_ONLY_MAIN_PROC_LOCK(c_p);
    }
    reg_safe_read_lock(c_p, &c_p_locks);

    if (c_p && !c_p_locks)
        erts_proc_lock(c_p, ERTS_PROC_LOCK_MAIN);

    hval = REG_HASH(name);
    ix = hval % process_reg.size;
    b = process_reg.bucket[ix];

    /*
     * Note: We have inlined the code from hash.c for speed.
     */

    while (b) {
	RegProc* rp = (RegProc *) b;
	if (rp->name == name) {
	    /*
	     * SMP NOTE: No need to lock registered entity since it cannot
	     * be removed without acquiring write reg lock and id on entity
	     * is read only.
	     */
	    if (rp->p)
		res = rp->p->common.id;
	    else if (rp->pt)
		res = rp->pt->common.id;
	    break;
	}
	b = b->next;
    }

    reg_read_unlock();

    ASSERT(is_internal_pid(res) || is_internal_port(res) || res==am_undefined);

    return res;
}
```

`reg_safe_read_lock` avoids deadlocks by relaxing the lock constraints held on
the `c_p` lock, allowing this function to read the registry but not block any
other process trying to do the same for the same name. Then a typical hash
bucket lookup is done. (The registry is a bunch of linked lists in an
array. `hval` is the index into that array.)

How does registration work? If we pop back to `bif.c` we'll find `register_2`:

```
BIF_RETTYPE register_2(BIF_ALIST_2)   /* (Atom, Pid|Port)   */
{
    if (erts_register_name(BIF_P, BIF_ARG_1, BIF_ARG_2))
	BIF_RET(am_true);
    else {
	BIF_ERROR(BIF_P, BADARG);
    }
}
```

The `erts_register_name` is the main show, returning 0 if the process is already
registered. It's defined in `register.c`:

```
int erts_register_name(Process *c_p, Eterm name, Eterm id)
{
    int res = 0;
    Process *proc = NULL;
    Port *port = NULL;
    RegProc r, *rp;
    ERTS_CHK_HAVE_ONLY_MAIN_PROC_LOCK(c_p);

    if (is_not_atom(name) || name == am_undefined)
	return res;

    if (c_p->common.id == id) /* A very common case I think... */
	proc = c_p;
    else {
	if (is_not_internal_pid(id) && is_not_internal_port(id))
	    return res;
	erts_proc_unlock(c_p, ERTS_PROC_LOCK_MAIN);
	if (is_internal_port(id)) {
	    port = erts_id2port(id);
	    if (!port)
		goto done;
	}
    }

    {
	ErtsProcLocks proc_locks = proc ? ERTS_PROC_LOCK_MAIN : 0;
	reg_safe_write_lock(proc, &proc_locks);

	if (proc && !proc_locks)
	    erts_proc_lock(c_p, ERTS_PROC_LOCK_MAIN);
    }

    if (is_internal_pid(id)) {
	if (!proc)
	    proc = erts_pid2proc(NULL, 0, id, ERTS_PROC_LOCK_MAIN);
	r.p = proc;
	if (!proc)
	    goto done;
	if (proc->common.u.alive.reg)
	    goto done;
	r.pt = NULL;
    }
    else {
	ASSERT(!INVALID_PORT(port, id));
	ERTS_LC_ASSERT(erts_lc_is_port_locked(port));
	r.pt = port;
	if (r.pt->common.u.alive.reg)
	    goto done;
	r.p = NULL;
    }

    r.name = name;

    rp = (RegProc*) hash_put(&process_reg, (void*) &r);
    if (proc && rp->p == proc) {
	if (IS_TRACED_FL(proc, F_TRACE_PROCS)) {
	    trace_proc(proc, ERTS_PROC_LOCK_MAIN,
                       proc, am_register, name);
	}
	proc->common.u.alive.reg = rp;
    }
    else if (port && rp->pt == port) {
    	if (IS_TRACED_FL(port, F_TRACE_PORTS)) {
		trace_port(port, am_register, name);
	}
	port->common.u.alive.reg = rp;
    }

    if ((rp->p && rp->p->common.id == id)
	|| (rp->pt && rp->pt->common.id == id)) {
	res = 1;
    }

 done:
    reg_write_unlock();
    if (port)
	erts_port_release(port);
    if (c_p != proc) {
	if (proc)
	    erts_proc_unlock(proc, ERTS_PROC_LOCK_MAIN);
	erts_proc_lock(c_p, ERTS_PROC_LOCK_MAIN);
    }
    return res;
}
```

Main chunk to be concerned with is this:

```
    {
	ErtsProcLocks proc_locks = proc ? ERTS_PROC_LOCK_MAIN : 0;
	reg_safe_write_lock(proc, &proc_locks);

	if (proc && !proc_locks)
	    erts_proc_lock(c_p, ERTS_PROC_LOCK_MAIN);
    }
```

The caller takes a safe write lock on the registry, then calls

```
    rp = (RegProc*) hash_put(&process_reg, (void*) &r);
```

`hash_put` is defined in `hash.c` and is a bucket inserter, returing (or
finding) the object in the hash table.

```
/*
** Find or insert an object in the hash table
*/
void* hash_put(Hash* h, void* tmpl)
{
    HashValue hval = h->fun.hash(tmpl);
    int ix = hval % h->size;
    HashBucket* b = h->bucket[ix];

    while(b != (HashBucket*) 0) {
	if ((b->hvalue == hval) && (h->fun.cmp(tmpl, (void*)b) == 0))
	    return (void*) b;
	b = b->next;
    }
    b = (HashBucket*) h->fun.alloc(tmpl);

    b->hvalue = hval;
    b->next = h->bucket[ix];
    h->bucket[ix] = b;

    if (++h->nobjs > h->grow_threshold)
	rehash(h, 1);
    return (void*) b;
}
```

That's it. A RW lock protected hash table.
