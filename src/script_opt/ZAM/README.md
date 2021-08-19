<h1 align="center">

ZAM Optimization: User's Guide

</h1><h4 align="center">

[_Overview_](#overview) -
[_Known Issues_](#known-issues) -
[_Optimization Options_](#script-optimization-options) -

</h4>


<br>

## Overview

Zeek's _ZAM optimization_ is an experimental feature that changes the
basic execution model for Zeek scripts in an effort to gain higher
performance.   Normally, Zeek parses scripts into _Abstract Syntax Trees_
that are then executed by recursively interpreting each node in a given
tree.  With script optimization, Zeek compiles the trees into a low-level
form that can generally be executed more efficiently.

You specify use of this feature by including `-O ZAM` on the command
line.  (Note that this option takes a few seconds to generate the ZAM code, unless you're using `-b` _bare mode_.)

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

* In addition, there are some
[types of scripts that currently can't be compiled](#Scripts-that-cannot-be-compiled),
and thus will remain interpreted.  If your processing bottlenecks in such
scripts, you won't see much in the way of gains.

<br>

## Known Issues


Here we list various issues with using script optimization, including both
deficiencies (problems to eventually fix) and incompatibilities (differences
in behavior from the default of script interpretation, not necessarily
fixable).  For each, the corresponding list is roughly ordered from
you're-most-likely-to-care-about-it to you're-less-likely-to-care, though
of course this varies for different users.
<br>

### Deficiencies to eventually fix:

* Error messages in compiled scripts often lack important identifying
information.

* The optimizer assumes you have ensured initialization of your variables.
If your script uses a variable that hasn't been set, the compiled code may
crash or behave aberrantly. You can use the `-u` command-line flag to find such potential usage issues.

* Certain complex "when" expressions may fail to reevaluate when elements
of the expression are modified by compiled scripts.

<br>

### Incompatibilities:

* When printing scripts (such as in some error messages), the names of
variables often reflect internal temporaries rather than the original
variables.

* The deprecated feature of intermixing vectors and scalars in operations
(e.g., `v2 = v1 * 3`) is not supported.

* The `same_object()` BiF will always deem two non-container values as
different.

<br>

### Scripts that cannot be compiled:

The ZAM optimizer does not compile scripts that include "when" statements or
lambda expressions.  These will take substantial work to support.  It also
will not inline such scripts, nor will it inline scripts that are either
directly or indirectly recursive.

You can get a list of non-compilable scripts using
`-O ZAM -O report-uncompilable`.  For recursive scripts, use
`-O report-recursive` (no `-O ZAM` required, since it doesn't apply to the
alternative optimization, `-O gen-C++`).

<br>


## Script Optimization Options

Users will generally simply use `-O ZAM` to invoke the script optimizer.
There are, however, a number of additional options, nearly all of which
only have relevance for those debugging optimization problems or performance
issues:

|Option|Meaning|
|---|---|
|`dump-uds`	|	Dump use-defs to _stdout_.|
|`dump-xform`	|	Dump transformed scripts to _stdout_.|
|`dump-ZAM`	|	Dump generated ZAM code to _stdout_.|
|`help`		|	Print this list.|
|`inline`		|	Inline function calls.|
|`no-ZAM-opt`	|	Turn off low-level ZAM optimization.|
|`optimize-all`	|	Optimize all scripts, even inlined ones. You need to separately specify which optimizations you want to apply, e.g., `-O inline -O xform`.|
|`optimize-AST`	|	Optimize the (transform) AST; implies `xform`.|
|`profile-ZAM`	|	Generate to _stdout_ a ZAM execution profile. (Requires configuring with `--enable-debug`.)|
|`report-recursive`	|	Report on recursive functions and exit.|
|`report-uncompilable`	|	Report on uncompilable functions and exit.|
|`xform`		|	Transform scripts to "reduced" form.|

<br>
<br>

