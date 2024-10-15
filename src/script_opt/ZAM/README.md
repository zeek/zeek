<h1 align="center">

ZAM Optimization: User's Guide

</h1><h4 align="center">

[_Overview_](#overview) -
[_Known Issues_](#known-issues) -
[_Optimization Options_](#script-optimization-options) -
[_ZAM Profiling_](#ZAM-profiling) -

</h4>


<br>

<a name="overview"></a>
## Overview

Zeek's _ZAM optimization_ is an experimental feature that changes the
basic execution model for Zeek scripts in an effort to gain higher
performance.   Normally, Zeek parses scripts into _Abstract Syntax Trees_
that are then executed by recursively interpreting each node in a given
tree.  With script optimization, Zeek compiles the trees into a low-level
form that can generally be executed more efficiently.

You specify use of this feature by including `-O ZAM` on the command line.
(Note that this option takes a few seconds to generate the ZAM code, unless
you're using `-b` _bare mode_.)

How much faster will your scripts run?  There's no simple answer to that.
It depends heavily on several factors:

* What proportion of the processing during execution is spent in Zeek's
_Event Engine_ rather than executing scripts.  ZAM optimization doesn't
help with Event Engine execution.

* What proportion of the script's processing is spent executing built-in
functions (BiFs).  ZAM optimization improves execution for some select,
_simple_ BiFs, like `network_time()`, but it doesn't help for complex BiFs.
It might well be that most of your script processing actually occurs inside
the _Logging Framework_, for example, and thus you won't see much improvement.

* Those two factors add up to gains very often on the order of only 10-15%,
rather than something a lot more dramatic.

<br>

<a name="known-issues"></a>
## Known Issues


Here we list various issues with using script optimization, including both
deficiencies (things that don't work as well as you might like)
and incompatibilities (differences in behavior from the default
of script interpretation).
<br>

### Deficiencies:

* The optimizer assumes you have ensured initialization of your variables.
If your script uses a variable that hasn't been set, the compiled code may
crash or behave aberrantly. You can use the `-u` command-line flag to find such potential usage issues.

* When printing scripts (such as in some error messages), the names of
variables often reflect internal temporaries rather than the original
variables.

<br>

### Incompatibilities:

* ZAM ignores `assert` statements.

* The `same_object()` BiF will always deem two non-container values as
different.

<br>

<a name="script-optimization-options"></a>
## Script Optimization Options

Users will generally simply use `-O ZAM` to invoke the script optimizer.
There are, however, a number of additional options, nearly all of which
only have relevance for those debugging optimization problems or performance
issues:

|Option|Meaning|
|---|---|
|`dump-uds`	|	Dump use-defs to _stdout_.|
|`dump-xform`	|	Dump transformed scripts to _stdout_.|
|`dump-ZAM`	|	Dump generated ZAM code to _stdout_, including intermediaries.|
|`dump-final-ZAM`	|	Dump final generated ZAM code to _stdout_.|
|`gen-ZAM-code`		|	Generate ZAM without additional optimizations.|
|`help`		|	Print this list.|
|`inline`		|	Inline function calls.|
|`no-inline`		|	Suppress inlining even if another option implies it.|
|`no-ZAM-opt`	|	Turn off low-level ZAM optimization.|
|`optimize-all`	|	Optimize all scripts, even inlined ones. You need to separately specify which optimizations you want to apply, e.g., `-O inline -O xform`.|
|`optimize-AST`	|	Optimize the (transform) AST; implies `xform`.|
|`profile-ZAM`	|	Generate to "zprof.out" a ZAM execution profile. (Requires configuring with `--enable-ZAM-profiling` or `--enable-debug`.)|
|`report-recursive`	|	Report on recursive functions and exit.|
|`report-uncompilable`	|	Report on uncompilable functions and exit. For ZAM, all functions should be compilable.|
|`validate-ZAM`		|	Perform internal validation of ZAM instructions and exit.|
|`xform`		|	Transform scripts to "reduced" form.|

<a name="ZAM-profiling"></a>
## ZAM Profiling

ZAM supports detailed script execution profiling, activated using `-O
profile-ZAM`. (This option implies `-O ZAM` unless you've already specified
some ZAM optimization options.) Profiles are written to `zprof.out`. These
profiles have a number of components, and are intended to be subsetted
(such as by using `grep`) and then further processed, such as by using
`sort` to pick out instances with large values.

When profiling, ZAM gathers for each function body its total number of
calls, total CPU time (including time spent in any script functions or
BiFs it calls), an estimate of total memory allocations, and the number
of sampled ZAM instructions (see below). Memory impact is done by comparing
Zeek's total memory usage when a function body starts with its total usage
when the body finishes. Any increase is charged against the function body;
decreases however are not (because it's not as clear whether they are
meaningful). This approach only approximates actual memory usage because
often allocations can be met by memory currently available at user level,
not requiring any kernel allocations; and if they _do_ require kernel
allocations, those can be significantly larger than the immediate need.
That said, experience finds that the resulting values (reported in bytes)
do generally reflect the execution's state-holding impact.

Often the report will state that a function body "did not execute" when
in fact you're sure it did. This arises due to ZAM's heavy use of _inlining_:
while the code of the function body did indeed execute, it did so only in
the context of _other_ function bodies, and that's where the CPU & memory
impact are charged. (You can suppress this by using `-O no-inline` to turn
off ZAM's inlining, although with a significant performance impact.)

In addition to per-function profiling, ZAM also profiles individual ZAM
instructions. Because fine-grained profiling of every instruction execution
imposes a significant performance penalty,
ZAM does instruction-level profiling using _sampling_.  The default sampling
rate is 1-in-100. (You can control it via the `ZEEK_ZAM_PROF_SAMPLING_RATE`
environment variable, and setting that variable to `1` effectively turns
off sampling). More frequent sampling rates slow down execution further but
provide more accurate information. With the default rate, the slowdown is
about 2x, so not something to use in production in its present form.

At the top of `zprof.out`, ZAM reports the sampling rate and also its
estimate of the cost to profiling a single ZAM instruction, and of assessing
memory impact. When reporting CPU times, ZAM subtracts off these costs.
(If the resulting value is negative, it's rounded up to 0.) Reported CPU
times do _not_ factor in the sampling rate, so for example if you want to
estimate the full impact of executing an instruction, when using the default
sampling rate you would multiple the reported value by 100.

For each profiled instruction, ZAM associates a _call tree_ reflecting
each function body and "statement block" leading up to the specific point
in the scripts for which the instruction executes. The call tree appears
after a `//` delimiter, such as this:

`
Config::config_option_changed 4 2 0.000009 load-val-VV-S 2 (Config::location), interpreter frame[2] // Site::zeek_init;Site::zeek_init:315-336;Site::zeek_init:326-329;Site::zeek_init:329;Site::update_private_address_space;Site::update_private_address_space:283-312;Site::update_private_address_space:310;Config::config_option_changed;Config::config_option_changed:142-151
`

This line is reporting a single ZAM `load-val-VV-S` instruction corresponding
to the `Config::config_option_changed` function body. The value of `4`
reflects the position of this instruction in the fully compiled body (the
instruction right above it will be numbered `3`). The `2` and `0.000009`
indicate that the instruction's execution was sampled two times, for a
total of 9 microseconds of CPU time. The text after `load-val-VV-S` up
through the `//` delimiter give some particulars of the instruction's
operands. What follows is then an accounting for the scripting leading to
the instruction's execution: it's coming from a `zeek_init` handler,
including a number of statement blocks (such as lines `315-336`), with the
final `zeek_init` statement being line `329`. At that point,
`Site::update_private_address_space` was called, and it in turn called
`Config::config_option_changed`. (The `Config::config_option_change` call
was not inlined; if it had been, then the label in the first column would
have been either `zeek_init` or `Site::update_private_address_space`.)

A key point about the format used here is that it's the same as used by
`flamegraph.pl` to generate _Flame Graphs_. Thus, you can generate a flame
graph of ZAM-compiled script execution using the following:

`
grep // zprof.out | awk '{ printf "%s %d\n", $NF, $4 * 1e8 }' | flamegraph.pl >my-flame-graph.svg
`

Here the `awk` invocation is printing out the call tree (`$NF`) followed
by the sampled CPU time multiplied by 100,000,000 to convert it to
microseconds and to expand it by the default sampling rate of 100.

The profile also computes per-module sampling statistics, which you can
examine using `grep ^module zprof.out`. These include lines like:

`
module Weird sampled CPU time 0.095283, 157523 sampled instructions
`

This summary is derived from all sampled instructions whose call tree
included some function from the `Weird` module.  As usual, you would
multiply the sampled values by the sampling rate to get the full estimated
values.

Finally, note that using ZAM profiling with its default sampling rate slows
down execution by 30-50%.

<br>
<br>

