<h1 align="center">

Script Optimization: User's Guide

</h1><h4 align="center">

[_Overview_](#overview) -
[_Known Issues_](#known-issues) -
[_ZAM files_](#ZAM-save-files) -
[_Optimization Options_](#script-optimization-options) -
[_Finding Usage Errors_](#finding-potential-usage-errors)

</h4>


<br>

Overview
--------

Zeek's _script optimization_ is an experimental feature that changes the basic execution model for Zeek scripts in an effort to gain higher performance.   Normally, Zeek parses scripts into _Abstract Syntax Trees_ that are then executed by recursively interpretating each node in a given tree.  With script optimization, Zeek compiles the trees into a low-level form that can generally be executed more efficiently.

You specify use of this feature by including `--optimize` on the command line.  The first time you invoke it, start-up will take a while due to the compilation phase.  After compiling the scripts, Zeek will generate [`.ZAM` files](#ZAM-save-files) representing the compiled program.  Future executions will load the files rather than recompiling the corresponding scripts, leading to faster startup. 

How much faster will your scripts run?  There's no simple answer to that.  It depends heavily on several factors:

* What proportion of the processing during execution is spent in Zeek's _Event Engine_ rather than executing scripts.  Script optimization doesn't help with Event Engine execution (other than in minor ways).

* What proportion of the script's processing is spent executing built-in functions (BiFs).  Script optimization improves execution for some select, _simple_ BiFs, like `network_time()`, but it doesn't help for complex BiFs.  It might well be that most of your script processing actually occurs inside the _Logging Framework_, for example, and thus you won't see much improvement.

* Those two factors add up to gains very often on the order of only 10-15%, rather than something a lot more dramatic.

* In addition, there are some [types of scripts that currently can't be compiled](#Scripts-that-cannot-be-compiled), and thus will remain interpreted.  If your processing bottlenecks in such scripts, you won't see much in the way of gains.

* If your overall execution is short, then the time for loading the `.ZAM` files (or, worse, compiling from scratch) can predominate.

All that said, I'm very interested in situations where the performance gains appear unsatisfying.

Finally, the machinery required by the script optimizer also offers an opportunity to find [potential usage errors](#Finding-Potential-Usage-Errors).

<br>


Known Issues
------------

Here we list various issues with using script optimization, including both deficiencies (problems to eventually fix) and incompatibilities (differences in behavior from the default of script interpretation, not necessarily fixable).  For each, the corresponding list is roughly ordered from you're-most-likely-to-care-about-it to you're-less-likely-to-care, though of course this varies for different users.
<br>

### Deficiencies to eventually fix:

* Building the branch requires a modern `awk`, such as `gawk` or `mawk`.  `gawk` is currently hardwired into `src/gen-compiler-templates.sh` because I lack the CMake skillz to configure this appropriately.

* [As noted below](#ZAM-Save-Files), you need to have write permission in the directories where any scripts reside in order to create `.ZAM` files in them.  See the discussion there for workarounds.

* If you run concurrent `zeek`'s, either via a cluster/zeekctl or parallelized btests, there's a race in which multiple `zeek` instances can try to write the same `.ZAM` file concurrently, or where one instance reads a `.ZAM` file that's only been partially written.  The workaround for this is to run a single `zeek` instance first to do the compilation; or use `-O no-load`.

* Error messages in compiled scripts often lack important identifying information.

* Related in part to the above, about 5% of the test suite fails when using script optimization.

* The optimizer assumes you have ensured initialization of your variables.  If your script uses a variable that hasn't been set, the compiled code may crash or behave aberrantly.  [See below](#Finding-Potential-Usage-Errors) for how to find such instances.

* Certain complex "when" expressions may fail to reevaluate when elements of the expression are modified by compiled scripts.

* Executing multiple instances of the same "for" loop concurrently (due to recursion) will lead to incorrect results.
<br>

### Incompatiblities:

* The interpreter allows vectors to have "holes" that simply do not have any value.  The script optimizer treats all vector elements as having a value.

* The interpreter is quite lax regarding the use of `vector of any` types.  In particular, it permits "mixed" vectors for which individual elements have different types.  The script optimizer requires all elements to have the same type, and provides run-time checking to enforce this.  If you truly need heterogeneous types, you can instead use `table[count] of any`.  These even support the common vector idiom of `x[|x|] = v` for appending a value `v` to the "end".

* When printing scripts (such as in some error messages), the names of variables often reflect internal temporaries rather than the original variables.

* The deprecated feature of intermixing vectors and scalars in operations (e.g., `v2 = v1 * 3`) is not supported.

* Boolean operations on vectors (e.g., `v1 && v2`) are not supported.

* The `same_object()` BiF will always deem two non-container values as different.

* The semantics of deleting a record field differ when the field is itself a record.  For the interpreter, the field is completely removed, whereas for compiled scripts, it is replaced with a completely empty record.
<br>

### Scripts that cannot be compiled:

The optimizer does not compile scripts that include "when" statements or lambda expressions.  These will take substantial work to support.
It also will not inline such scripts, nor will it inline scripts that are either directly or indirectly recursive.

You can get a list of non-compilable scripts using `-O uncompilable`.  For recursive scripts, use `-O recursive`.

<br>


ZAM Save Files
--------------

Since script optimization can take significant time for complex scripts, by default the optimizer saves a representation of each compiled script in a `.ZAM` file.  When the optimizer is about to compile a script, it first checks for a corresponding `.ZAM` file, and if present it loads the compiled script from the file instead, saving considerable time.  (Startup is still noticeably slower than if not using optimization at all.)

**Important**: the presence of a `.ZAM` file does _not_ lead Zeek to load it unless you have also specified ``--optimize`` on the command line.

One issue with save files concerns correctness: if the script's statements, or any values used to compile it, change, then the save file will be _stale_ and yield incorrect results if used.  The optimzer attempts to avoid this problem by naming each file using a _hash_ of the script's statements and expressions.  For example, the file
```
init-bare.zeek#net_done:1853.648e554a7f2ba77b.ZAM
```
holds the ZAM code for the `net_done` event found on line 1853 of the file `init-bar.zeek`.  When compiled, the event handler had a hash of `648e554a7f2ba77b`, and this save file will only be used in lieu of recompiling `net_done` if the hashes match.

You might encounter multiple `.ZAM` files for the same function for which each is potentially valid, depending on what _other_ scripts are loaded concurrently. (For example, scripts that might extend the `connection` record type with additional fields.)

There is never any semantic harm in deleting `.ZAM` files if you're unsure whether they're stale.  You simply will have to wait longer when re-invoking Zeek for the optimizer to compile functions.

To allow ready association between `.ZAM` files and their corresponding scripts, Zeek stores them in the same directory from where it loaded the script.  This of course requires *write permission* for that directory, which you might not have if you install Zeek using `sudo make install` or such.  Given that script optimization is an **experimental** feature, for now I suggest that you instead install this verison of Zeek in a private directory to which you have write permission.

Zeek does not gracefully handle the situation where you do not have write permission.  You can work around this problem using `--optimize -O no-save`, but then you will have to abide slow startup times.  Alternatively, you could consider executing a single run of `sudo zeek --optimize my-script` to compile the scripts used by `my-script`.

Note: ZAM files have an ASCII representation, but it is not meant to be human-understandable, and we do not document it further.

<br>


Script Optimization Options
---------------------------

Users will generally simply use `--optimize` to invoke the script optimizer.  There are, however, a number of additional options, nearly all of which only have relevance for those debugging optimization problems or performance issues:

|Option|Meaning|
|---|---|
|`all`		|	Turn on `compile`, `inline`, and `xform-opt`.  This is the default for `--optimize` without any arguments.|
|`compile`	|	Compile scripts to ZAM code.  Implies `xform`.|
|`delete`		|	Delete any saved ZAM code.  Implies `no-load`.|
|`dump-code`	|	Dump ZAM code to _stdout_.|
|`dump-max-rds`	|	Dump maximal reaching-defs to _stdout_.|
|`dump-min-rds`	|	Dump minimal reaching-defs to _stdout_.|
|`dump-uds`	|	Dump use-defs to _stdout_.|
|`dump-xform`	|	Dump transformed scripts to _stdout_.|
|`help`		|	Print this list.|
|`inline`		|	Inline function calls.|
|`no-load`	|	Do not load saved ZAM code.|
|`no-save`	|	Do not save ZAM code.|
|`no-ZAM-opt`	|	Turn off low-level ZAM optimization.|
|`overwrite`	|	Overwrite saved ZAM code.|
|`profile`	|	Generate to _stdout_ a ZAM execution profile.|
|`recursive`	|	Report on recursive functions and exit.|
|`uncompilable`	|	Report on uncompilable functions and exit.|
|`unused`		|	Report on unused functions and events, and exit.|
|`xform`		|	Tranform scripts to "reduced" form.|
|`xform-opt`	|	Optimize "reduced" form scripts; implies `xform`.|

<br>
For all of these, you can use `-O _option_` to specify them rather than spelling out `--optimize`.  (You cannot, however, use `-O` as an alternative to a bare `--optimize`.)

<br>
<br>
Users might find three options helpful in understanding the optimization of their scripts.  `recursive` and `uncompilable` provide insight into scripts that cannot be inlined or even compiled.  `unused` looks for functions that are never called or events that are never generated.  **Note**: this last will generally flag many such functions and events, due to their presence in the standard scripts but lack of use for your particular script.  However, it can be worth wading through the output to find functions or events of particular interest to you, as these (especially the latter) can otherwise be difficult to spot.  Also, some events reported as ungenerated are in fact generated if you use an associated plugin.  (And others might be generated by the event engine, but not using its standard registration method, which this analysis relies on.)

<br>
<br>

Finding Potential Usage Errors
------------------------------

The algorithms needed for script optimization also enable identifying certain forms of _usage errors_.  These concern variables used-but-not-guaranteed-set or set-but-not-ever-used.  Zeek generates reports for these if you specify the `-u` flag.  It exits after producing the report, so if it simply exits with no output, then it did not find any usage errors.

Variables reported as "used without definition" appear to have a code path to them the could access their value even though it has not been initialized.  _The optimizer may not generate correct code in this case._  If upon inspection you determine that there is no actual hazard, you can mark the definition with an `&is_set` attribute to assure the optimizer that the value will be set.

Variables reported as "assignment unused" have a value assigned to them that is meaningless since prior to any use of that value, another value is assigned to the same variable.  Such assignments are worth inspecting as they sometimes reflect logic errors.  The optimizer should always be correct in identifying an unused assignment (let me know if it blows it!), but if you still want it you can suppress the report by adding an `&is_used` attribute to the original definition.

You can run the above analysis on not just variables but also record fields by specifying `-uu`.  This takes much longer, and flags numerous points in the installed scripts that have potential usage problems (though the ones I've checked all have exterior logic that ensures the problem can't actually happen.)  It can however be worth trying and confining your assessment of what it flags to your own scripts rather than the installed ones, as these can represent hard-to-find bugs.
