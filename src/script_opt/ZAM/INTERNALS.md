<h1 align="center">

ZAM Optimization: Internals

</h1><h4 align="center">

[_Overview_](#overview) -
[_Source Code_](#layout) -
[_High Level_](#high-level) -
[_Inlining_](#inlining) -
[_AST Profiling_](#ast-profiling) -
[_AST Reduction_](#reduction) -
[_AST Analysis_](#ast-analysis) -
[_AST Optimization_](#ast-opt) -
[_Properties of BiFs_](#bif-properties) -
[_Zeek Abstract Machine_](#zeek-abstract-machine) -
[_Compiling to ZAM_](#compile-to-zam) -
[_Finalizing ZAM Compilation_](#finalizing) -
[_ZAM Execution_](#execution) -
[_Troubleshooting_](#trouble) -
[_BTests_](#btests) -


</h4>

<br>

<a name="overview"></a>
## Overview

### How Things Work Without ZAM
During initializing, Zeek parses the provided scripts to translate them
into Abstract Syntax Trees (ASTs), with one AST associated with each
*function* (a term we use to also include single instances of an event handler
or hook body).  The ASTs consist of two basic types of nodes, "statements"
(derived from the `Stmt` class) and "expressions" (derived from `Expr`). The
root of a function's AST is a `Stmt` node, very often in particular a `StmtList`
node which is a statement comprised of a list of child `Stmt` nodes.

`Stmt` nodes have `Execute` methods that when called perform the operation
corresponding to a script statement. Often, this execution in turn evaluates
`Expr` nodes, which is done via `Eval` methods.  The `Eval` methods return `Val`
objects, often newly constructed, which are used to hold the full range
of Zeek data type values (e.g., `interval` or `table`). Global script
variables have a single `Val` associated with their _identifier_
(an `ID` object). Local variables reside at a specific position in a `Frame`
object associated with an instance of the function's execution.

In Zeek's default operation, every time a function is called - either due
to an event being generated, another function calling the function, or
in some situations the event engine calling a function directly - the
arguments, which are (pointers to) `Val` objects, are copied into the `Frame` at specific
locations, and then Zeek's *script interpreter* evaluates the AST by
calling its top-level node's `Execute` method. That call in turn recursively
calls the `Execute` methods of the node's children, some of which will then
call expression `Eval` methods; those will often recurse, and can also lead
to further function calls.

### ZAM's General Approach

This approach of using an interpreter to recursively execute the AST has
the benefit of being easy to implement and extend. However, it is very
heavy in terms of C++ method calls and `Val` object creation (and dynamic memory allocation) and manipulation,
which leads to inefficient performance.

**ZAM** (Zeek Abstract Machine) script optimization aims for higher script
performance by switching execution to a model that, while still interpreted,
is much lower level, and as a consequence can avoid nearly all function
calls (other than initial ones) and greatly reduce the creation and manipulation
of `Val` objects. It does so by translating the ASTs into operations in a
custom byte-code-style instruction set. The function body's AST is replaced
by an array of these instructions. When executing the function, a program
counter (PC) repeatedly indexes the array to locate the next
instruction to evaluate. This approach reduces the use of recursive
method calls to instead be a loop that fetches an instruction to execute,
dispatches it via a huge C++ `switch` statement, then
typically increments the PC (but could instead assign it to a value
to effect a branch), and continues until a `return` instruction executes,
or the PC reaches the end of the instruction array.

The user activates ZAM optimization by specifying `-O ZAM` on the command
line (or setting the `$ZEEK_ZAM` environment variable to a non-zero value).

Overall, ZAM's design has been governed by the goals of (1) simple
workflow for the user (just adding an argument to the command line, without
any need for separate builds) and (2) full interoperability with
non-optimized scripts and event engine internals.

An alternative form of script optimization, `-O gen-C++`, translates
the original ASTs into C++ code, which then is compiled directly
into Zeek. (Thus, this form has a more complex workflow than the simplicity
of simply specifying `-O ZAM` on the command line.) The implementation of
this form of script optimization shares some functionality with that for
ZAM - option processing, AST profiling, and some properties computed
for statement bodies and globals - but for the most part the two
implementations are separate.


<a name="layout"></a>
## Source Code Layout

The elements of ZAM's implementation appear in several places:

* `src/`
	The most significant script optimization elements at the top
	level are extensions to the `Expr` and `Stmt` classes to add
	methods for analyzing the properties of AST nodes and for
	transforming their representation in various ways for [AST
	reduction](#reduction) (see below). There are also minor top-level changes
	to Zeek's option processing to control the usage of script
	optimization.

* `src/script_opt/`
	The overall drivers for script optimization (both ZAM and
	compiling-to-C++), including option processing, and classes for
	analyzing and manipulating ASTs (see [AST Reduction](#reduction) below). Not
	much of this is ZAM-specific, although the AST manipulations are
	currently only used by ZAM.

* `src/script_opt/ZAM/`
	The ZAM compiler and associated ZAM-specific code. This processing
	is done once ASTs are fully reduced, per [AST Reduction](#reduction). Each
	instance of the compiler takes a function and its associated AST
	body and replaces the AST body with a `ZBody` object that interprets
	the resulting byte code. For event handlers and hooks with multiple
	bodies, each body is compiled separately (however, see [event
	handler coalescence](#coal) below).

* `src/script_opt/ZAM/OPs/`
	The collection of templates describing low-level (byte code) ZAM
	operations. These are processed by `gen-zam` to create various C++
	include files used for ZAM compilation and execution. There's a
	lengthy [`README.txt`](https://github.com/zeek/zeek/blob/master/src/script_opt/ZAM/OPs/README.txt) describing the templating language.

* `src/script_opt/ZAM/maint/`
	Scripts for ZAM maintenance.  Currently, there's just one, for
	finding Zeek functions that are known to the event engine. These
	are always treated as potentially recursive (a distinction used
	by ZAM to determine whether it needs to avoid certain optimizations).
	See the associated [`README`](https://github.com/zeek/zeek/blob/master/src/script_opt/ZAM/maint/README) for more information.

* `auxil/gen-zam/`
	The `gen-zam` utility reads in ZAM operation templates and generates
	the C++ files needed to implement the instructions.


<a name="high-level"></a>
## High-level compilation process

ZAM compilation proceeds along the following steps:

1. Zeek parses all of the scripts and translates them to ASTs, as normal.
Upon finishing each function, it's noted for potential script optimization
analysis (via a call to `analyze_func()`); for event handlers and hooks
with multiple bodies, this is done per-body.  Similarly, lambda expressions
are remembered (via a call to `analyze_lambda()`), including the internal
lambdas used by `when` expressions (`analyze_when_lambda()`). If the scripts
include any global statements, those are treated as an additional function
(`analyze_global_stmts()`).

1. Zeek's setup calls `analyze_scripts()` to now collectively analyze/compile
the various functions/events/hooks.

1. Non-recursive function calls are recursively [_inlined_](#inlining) (as long as not too
large), to eliminate function call overhead and facilitate optimization
across function calls.

1. Each function body's AST is [_profiled_](#ast-profiling) to determine a large number
of properties (such as which locals and globals it uses, a list of all
of its `Expr` and `Stmt` AST nodes, constants, type aliases, etc.).

1. For each function being optimized, its AST is [_reduced_](#reduction) to a simplified
form suitable conducive to analysis and directly translatable into ZAM
operations.

1. The reduced AST is [_analyzed_](#ast-analysis) to enable [_optimization_](#ast-opt) such as (among other things) by propagating
constants, eliminating recomputation of common subexpressions, and removing
assignments that won't ultimately be used.

1. The optimized AST is [compiled](#compile-to-zam) into an initial ZAM program. Most
AST `Expr` nodes translate into a single ZAM operation, while `Stmt`
nodes might result in a few (but not a lot of) operations. Control flow
at this point is in terms of low-level _gotos_.

1. ZAM's [low-level optimizer](#finalizing) processes the initial program for further
improvements. These include collapsing chains of branches, eliminating
unused assignments and other dead code, and coalescing variables whose
usage does not overlap into a shared `ZVal` frame element.

1. At this point, the function's body (which is a single `Stmt` node, though
often that `Stmt` is a `StmtList` that includes multiple `Stmt`s) is
replaced by a `ZBody` node. `ZBody`s are a subclass of `Stmt` so the change
works in a manner fully compatible with non-optimized scripts.

1. After all scripts have been compiled and the global statements executed,
`clear_script_analysis()` recovers the considerable additional memory
allocated during script optimization.

Below there's a section for each of these steps other than the first two
and the last (given their simplicity), along with a section for [how `ZBody`
execution works](#execution).

<a name="inlining"></a>
## Inlining

Zeek scripts represent function calls with `CallExpr` AST nodes.
To (greatly) reduce the number of calls, the [_inliner_](https://github.com/zeek/zeek/blob/master/src/script_opt/Inline.cc) replaces most instances of such nodes
with a special `InlineExpr` node. The exceptions are:

* _Built-in functions_ (BiFs). A possible future optimization would
be to extend the `bifcl` BiF compiler to generate versions of BiFs
that ZAM could call directly, rather than needing to go through the
fairly heavyweight `Func::Invoke()` interface.

* _Recursive functions_. Inlining these could of course lead to infinite
expansion. (In principle they could be inlined up to a point, but this
doesn't seem worth the effort.)  The inliner computes the transitive closure
of which-function-calls-which in order to identify both direct and indirect
recursion. It turns out that recursive Zeek functions are quite rare,
though there are a few.

* _Functions that make indirect calls_ (i.e., via a `function` variable or
value) are presumed to be potentially recursive and are skipped. These
are likewise rare.

* _Functions called by the event engine_ are likewise skipped,
as these might be recursive. They could in fact be inlined (though it's
unlikely they will be also called by script functions) since doing so won't
blow them up, but again it doesn't appear to be worth the effort, and
it's useful for other optimizations to flag them as potentially recursive.

* _Event handlers_ are irrelevant for inlining since they cannot be directly
called by a script.

* _Hooks_ in principle _could_ be inlined, but since they contain multiple
bodies this is a bit tricky, so presently they aren't. (However, see the following discussion.)

<a name="coal"></a>
Before proceeding, the inliner identifies event handlers with multiple
bodies and _coalesces_ them into a single body (subject to some sizing
constraints), essentially replacing the collection with a single body
that "calls" each body in turn.

Inlining the calls of each candidate function proceeds recursively.  `Stmt`
AST nodes support a (new) `Inline` method that traverses the node's children
to identify any `CallExpr` nodes. These are replaced with `InlineExpr`
nodes and the result recursively expanded to continue inlining any
callees-of-the-callees. When a call is inlined, the AST body of the inlined
function is _duplicated_ (rather than referred to directly), using the (new) `Duplicate()`
method that AST nodes now support. Doing so is important, as otherwise
optimizations that are valid for one call to the inlined function can alter
other instances of calls to that function where the optimization is not
in fact valid.

When inlining an AST, variables in the inlined function's body have _`.n`_ appended to their names, where `n` reflects the inlining depth. This is done in order to avoid name collisions with outer variables that use the same name.

The inliner tracks the complexity (in terms of number of AST nodes)
of a function body as it's progressively inlined, and stops if the
size exceeds a threshold. Doing so helps reduce the time needed for
ZAM compilation, as without this cap, some functions can get quite huge
and subsequent analyses running on them will take a very long time.

The inliner also tracks those functions that have had all of their
instances (locations where they are called) inlined. There's no need to
compile these functions further, since they won't ever be called directly,
and as this includes a large number of functions, doing so is a
significant gain for ZAM compilation time.

Note that the result of inlining a function continues to be an AST that
Zeek's interpreter can execute. Because of this you might think that
we can speed up interpreted script execution by just using the inliner,
but it turns out to not yield much direct gain by itself, only when
fully compiled to ZAM.

For debugging and maintenance purposes, you can explicitly enable inlining
using `-O inline`. If that's the only script-optimization-related
option given on the command line then script bodies will be inlined but
otherwise unmodified. You can also use `-O no-inline` to turn inlining _off_
but otherwise perform script optimization, which is helpful for determining
whether or not a problem is due to inlining.

<a name="ast-profiling"></a>
## AST Profiling

Each function body is profiled by recursively traversing its AST to inspect
all of its elements. The full collection of function bodies is then
_globally_ profiled (such as what are all the globals and types used).
See the extensive comment at the beginning of [`src/script_opt/ProfileFunc.h`](https://github.com/zeek/zeek/blob/master/src/script_opt/ProfileFunc.h)
for a discussion of various considerations for constructing these profiles.

<a name="reduction"></a>
## AST Reduction

The goal of AST _reduction_ is to transform an AST into a form where each
element is as simple as it can be. For expressions, this means that either
it's simply a constant or a variable (referred to as _singletons_),
or it's an assignment to an operation all of whose operands are singletons.
Statements are in reduced form if any expressions they refer to are either
just singletons, or in some cases very simple expressions (such as reduced
conditional expressions for `if` statements). Note that the end result of
AST reduction is still an AST executable by the interpreter; however, it generally runs inefficiently
since it has many more assignments and local (temporary) variables than the original.

Reduced ASTs are much closer in structure to ZAM's low-level instructions -
which for the most part are in terms of a few variables and possibly a
single constant - and thus conducive to translation into the byte code.
In addition, reduced ASTs are much easier to reason about (such as whether
an occurrence of given expression can be replaced by a variable previously
computed to hold that same expression).

To transform expressions into a form that can be represented by singletons requires creating
numerous temporary variables to hold intermediary values. At this stage,
temporaries are treated like other local variables (and allocated their
own slot in the `Frame` object used when the interpreter executes a
function body). They have one important property, which is they are only
assigned a value once, which makes it easier to reason about the safety
of their subsequent usage. Later optimization has stages to determine when
temporaries can be _doubled up_ and, essentially, reused.

Reduction also provides an opportunity to *fold* expressions with constant
operands into a single constant value, and to apply simplifications when
some-but-not-all of an expression's operands are constant, such as reducing
`x + 0` to `x`.

Reduction occurs recursively: AST node classes provide `Reduce()` methods
that generally first reduce their operands and then their own representation.
The process is done in the context of a `Reducer` object. It manages
temporary variables (including additional ones used to support inlining)
and a number of AST optimizations. Reduction proceeds with an initial recursive
pass over a function body's AST to transform it into reduced form, and then
a second optimization pass that leverages analysis of the reduced form to
identify opportunities for constant propagation, assignment elimination, and
the like ([see below](#ast-opt)).

Along with the `Reduce()` method, AST node classes provide additional
reduction-related methods. `IsReduced()` returns true if the given node
is in a reduced form. If the node isn't, it calls `NonReduced()`, which
remembers the node in a global variable that can be inspected when debugging
problems where ASTs fail to fully reduce. `HasReducedOps()` returns true
if all of the operands of a node are reduced; this is potentially different
than `IsReduced()` because the latter has the form of either a singleton or
an assignment to an expression with singleton operands, whereas
`HasReducedOps()` only refers to the operands, without having an
assignment. So, for example, `tmp = a + b` is in reduced form, while
`a + b` has reduced operands.

Some AST nodes transform when reduced into fully different representations.
For example, `++x` reduces to `x = x + 1` - changing from an Increment
node to an assignment to an Add node. The predicate `WillTransform()`
identifies these. In addition, some nodes transform when present in
conditionals, but not otherwise. For example, in isolation `x && y`
will reduce to `tmp = x && y`, but in a conditional such as `if ( x && y ) S`
it will transform into `if ( x ) { if ( y ) S }` (in order to preserve the
property of not even evaluating `y` if `x` is false). These sorts
of constructs are flagged using the `WillTransformInConditional()` predicate.

Note that the process of reduction generally only creates new nodes when a
node changes its type (such as the `++x` example above), or for assigning
an expression's value to a temporary. Otherwise, nodes are altered in place,
in order to diminish the memory allocation/deallocation churn that would
otherwise result.

When new nodes are created, however, it's important that they have the
same _location_ information associated with them as that for the original
nodes from which they're derived. This aids both pinpointing warnings and
error messages, and enables script-line-level ZAM profiling (not yet documented).
To make this easy to implement, a helper function `with_location_of()`
sets the location of one (new) node to that of an existing node.

Along with adding new AST methods to support reduction, script optimization
also introduces new types of AST nodes that are not needed by regular
interpreted execution:

* `InlineExpr` nodes replace `CallExpr` nodes during inlining, and these transform into `CatchReturnStmt` nodes during reduction. ([See below](#catchreturn).)

* `CheckAnyLenStmt` nodes provide a run-time check when assigning multiple variables to a single `any` value (a non-obvious language feature!). It
	also has a counterpart, `AnyIndexExpr`, to capture the assignment
	itself.

* `AppendTo` nodes replace `x += y` expressions when `x` is a `vector`
	and therefore the expression is an append operation rather than
	an add-to operation.

* `IndexAssignExpr` nodes replace assignments of the form `x[y] = z`
	with a three-operand expression.

* `FieldLHSAssignExpr` similarly replace assignments of the form
	`x$field = y`.

* `AssignRecordFieldsExpr` nodes are an internal optimization used
	when a series of assignments updates a number of fields in one
	record with values taken from another record.

* `AddRecordFieldsExpr` nodes are an internal optimization used
	when a series of `+=` assignments updates a number of fields in one
	record with values taken from another record.

* `ConstructFromRecordExpr` nodes are an internal optimization when
	a record constructor directly uses a number of fields from the
	same type of record.

* `CoerceFromAnyVecExpr` nodes are added when a `vector of any`
	vector is used in a context where a _concrete_ vector is expected.

* `ScriptOptBuiltinExpr` nodes replace certain scripting idioms
	with a custom instruction (that can then be translated into a
	single ZAM operation). See the discussion of [optimization](#ast-opt)
	below for further details.

* `NopExpr` is a dummy expression used as a placeholder for expressions
	that have been elided as unnecessary.

<a name="catchreturn"></a>
* `CatchReturnStmt` is used for inlining. It executes a block of code until it executes a `return` statement (or comes to the end of the block), and, if appropriate, assigns to a special return-value variable if the `return` includes an expression.  

For maintenance, you can run with _only_ transform-to-reduced-form turned on by
specifying `-O xform`. (You can combine this with other options, too, like
`-O inline`.)

<a name="ast-analysis"></a>
## AST Analysis

After transforming the AST to reduced form comes the AST-level optimization
phase. This begins with a traversal of the reduced AST to compute information
about the usage of the variables (_identifiers_, corresponding to `ID` objects)
present in the AST, including newly introduced temporaries.

Two key properties for AST optimization are analyzing a variable's [_reaching
definitions_](#reaching) and a statement's [_use definitions_](#use-def)
(or "use-defs").
Note that these are standard notions for compiler optimization, as is the
related notion of _confluence_ discussed below - they're not home-grown
concepts.  The same is true for the notion of converting the AST to _reduced_
form.

We now discuss each notion in turn, and then how they're leveraged for optimization.

<a name="reaching"></a>
### Reaching Definitions

A variable's reaching definitions reflect where in the AST the variable's
value is one of: (1) unassigned, (2) definitely assigned to a given value, (3)
definitely assigned but to an uncertain value, (4) _maybe_ assigned but
also maybe not.  These are computed in terms of their state _prior_ to
execution of a statement.  For example, in this code block:

```
	1. local a: int;
	2. local b: int;
	3. a = x + y;
	4. if ( foo_condition )
		5. b = a * a;
		6. a = x + z;
	7. print a, b;
	8. print x + y;
```

Before the execution of statements 1 and 2, the values of `a` and `b` are
unassigned, and the same holds before statement 3. Before the execution
of statement 4 `a` is _definitely assigned_ (and `b` is unassigned), and
`a`s associated expression is `x + y`. The same holds at the beginning
of statement 5. (In this and later examples for simplicity we confine our
discussion to `a` and `b`, and don't expand the discussion to other variables
like `x`.)

At the beginning of statement 6, `a` and `b` are both _definitely assigned_,
with `b` having an associated expression of `a * a` (note that here it
matters _which_ reaching-definition of `a` is reflected in the expression
`a * a`). At the beginning of statement 7, `a` is
definitely-assigned-but-to-an-uncertain-value, and `b` is maybe-assigned
(so we can flag a potential used-but-not-set usage error in the print
statement). The same holds at the beginning of statement 8. Because of
that, the optimizer can tell that it's not safe to replace `x + y` with
`a`, even though `a` was previously assigned to that expression. If we
removed statement 6, however, then `a`s reaching definition at statement
8 would be definitely-assigned with an associated expression of `x + y`,
and we _could_ transform statement 8 into `print a`.

While in the above example it's straightforward how to compute reaching
definitions for `a` and `b`, this becomes trickier in the face of loops.
For example, if the above were instead:

```
	1. local a: int;
	2. local b: int;
	3. a = x + y;
	4. for ( [x2, y2] in my_tbl )
		5. b = a * a;
		6. a = x2 + y2;
	7. print a, b;
	8. print x + y;
```

then the reaching definition of `a` before statement 4 is
definitely-assigned-but-to-an-uncertain-value, and for `b` it is
maybe-assigned.  This is because we may be arriving at the beginning of
the `for` loop at statement 4 for a second time, having already gone through
the loop once.  Hence, `a` at the beginning of statement 4 might have the
assignment value of `x + y`, or it might have the value of `x2 + y2`. `b`
might be unassigned, or it might be assigned to `a * a` (and that expression
itself reflects an uncertain value of `a`).

Computing reaching definitions in the presence of loops, switches, and
if-else structures is done by introducing the notion of control flow
_confluence_. Confluence refers to control flow either splitting from one
point into multiple paths (such as due to if-else or switch structures),
or multiple paths re-converging at a single point (such as due to loops,
`break`, `next`, `fallthrough`, and also at the end of if-else and switch
structures). The rules for propagating reaching definitions through
confluence regions are fairly simple: on a split, the reaching definitions
of a variable travel down both paths. At a merge, if all paths coming into
the merge have the same reaching definition for a variable, it retains its
definitely-define status (though perhaps with a different associated
expression, as long as all of the inbound paths agree on that expression).
If all paths have _some_ reaching definition, but some of these differ,
then the new reaching definition is
definitely-assigned-but-to-an-uncertain-value.  If some of the paths have
_no_ reaching definition while others do have a definition, then the
variable is maybe-defined. If none of them do, then it's unassigned.

The one trickiness here is that loops need to be visited multiple times:
first to propagate the reaching definitions upon the initial arrival at
the start of the loop, and then again to merge into those the reaching
definitions at active at the end of the loop, and then to re-propagate
those updated values through the loop's body.

The reaching-definitions analysis also provides the basis for Zeek's `-u`
_used without definition_ and _possibly used without definition_ warnings.  (Another version of the former is generated by ZAM's low-level instruction analyzer.)


<a name="use-def"></a>
### Use-Defs

A statement's use-defs refer to all of the variable definitions that are
used _after_ execution of that statement, where "after" means in a
control-flow sense.  Use-defs are computed by conducting a _reverse_
traversal of the AST, which we will illustrate here using the previous example:

```
	1. local a: int;
	2. local b: int;
	3. a = x + y;
	4. for ( [x2, y2] in my_tbl )
		5. b = a * a;
		6. a = x2 + y2;
	7. print a, b;
	8. print x + y;
```

After statements 8 and 7, neither `a` nor `b` is used.
We then back up to statement 4, since that's the previous statement
in the outer block. After 4, `a` and `b` are both used. We then propagate
that information to the analysis of statement 6: after it, both `a` and
`b` are used. However, after statement 5, only `b` is used, since `a`
was reassigned at statement 5. _Before_ statement 5, `a` is used (as
the RHS of the assignment), but `b` is not.

We then need to revisit the beginning of the loop (statement 4), computing
_confluence_ of `a`-is-used with `a`-and-`b`-are-used, which here is done
by union operations, so we keep `a`-and-`b`-are-used for statement 4.
This means that after statement 3, `a`-and-`b` are used, but after statement
2 (and statement 1), only `b` is used - which looks weird, because it's
unassigned at that point, but the notion is that its current value can be
subsequently used, whether assigned-or-not, while the current value of `a`
after statement 2 will _not_ be used, since it's reassigned right after
statement 2.

The use-def analysis also provides the basis Zeek's `-u`
_assignment unused_ warning.


<a name="ast-opt"></a>
## AST Optimization Elements

Once the above properties are computed, the `Reducer` object makes a
second reduction pass over the AST. This has several elements.

### Constant propagation

For an assignment of the form `x = c`, where `c` is a constant,
the optimizer replaces any subsequent use of exactly that instance
of `x` (and not any other possible instances of `x`) with `c`. (Mechanistically,
this is done by AST nodes in their `Reduce()` methods calling
the `Reducer` object's `UpdateExpr()` method.) This change
may then provide opportunities for either _folding_ (evaluating
at compile time any expression for which all of the operands
are constants, and replacing the expression's AST node with
a new one that just holds the resulting constant) or further
constant propagation, for example if later the assignment
`y = x` appears. That would be transformed into `y = c` and then
subsequent uses of `y` also are potential opportunities for
constant propagation.

Note that a `const` global can also be treated as a constant
in this context, since there's no way to alter its value during
script execution.


<a name="unused-assignments"></a>
### Removal of unused assignments

If there's an assignment of the form `x = y` (where `y` might be
a constant or an expression rather than a simple variable), and
the use-defs reveal that there's no subsequent use of `x`,
then the optimizer removes the assignment. (Note that at this point
perhaps there's no use of `y` after its earlier assignment, and if not then it
can be removed, too.) You might think that such assignments
are rare, but these situations (as well as the next one) actually
can be quite common for the temporary variables introduced during
AST reduction.

### Assignment cascades

A sequence like `x = a; y = x` can be replaced by `y = a`.
This might render `x` removable per the above discussion.

### Dead code removal

If a statement cannot be reached, it's safe to remove it.
The main benefit of doing so is that it can unearth what are
now [_unused assignments_](#unused-assignments) (see above).

### Common subexpression elimination (CSE)

CSE is a powerful optimization that identifies expressions
that do not require computing because their value is already
available in a variable. It is especially apt for optimizing
Zeek scripts because script writers often repeat expressions
rather than factor their code, for example in sequences like:

```
	c$conn$x = ...
	c$conn$y = ...
```

The interpreter will compute `c$conn` twice, but the optimizer
will transform this to

```
	tmp = c$conn;
	tmp$x = ...
	tmp$y = ...
```

and avoid the second computation.

Given Zeek's semantics, determining that it is _safe_ to substitute
a previous computation of an expression turns out to be quite
complex. To illustrate, consider the following code fragment:

```
	x = r1$f1 + r2$f2;
	...
	y = r1$f1 + r2$f2;
```

For it to be safe to transform the final statement into `y = x`
first requires that the _reaching definitions_ of `r1` and `r2`
are identical at the final statement. In addition, the use-def
of `x` at the statement needs to come (only) from the first
statement.

Even that is not enough, however. Consider the following larger
sequence:

```
	x = r1$f1 + r2$f2;
	z = r1;
	z$f1 = something_else;
	...
	y = r1$f1 + r2$f2;
```

Because `z` is a _shallow_ copy of `r1`, changing `z`s `$f1` field
also changes `r1`'s. Note that it's not enough to look for assignments
to `r1` like at the 2nd line in the example; suppose `z` is a record of the same
type as `r1` that's passed in as a parameter (or retrieved from a
table, or as a subrecord of another record, or ...). Then it could
_still_ be an alias for `r1`. In general, if the expression of
interest (`r1$f1 + r2$f2`) contains any _aggregates_ (tables, sets,
record, vectors), then any comparable modification to any
aggregate of the same type renders the CSE replacement potentially
unsafe.

In addition, consider:

```
	x = r1$f1 + r2$f2;
	noninlined_func();
	...
	y = r1$f1 + r2$f2;
```

Perhaps function `noninlined_func` modifies a global record that
happens to be aliased to `r1` - then the CSE is invalid. (Note that
`noninlined_func` might be a BiF. Most of these have no side effects
along these lines, but a few of them might - or might call script-level
functions that do. We discuss BiF properties further [below](#bif-properties).)

In fact, it's worse than that. Suppose we have:

```
	x = r1$f1 + r2$f2;
	tbl[foo] = something_else;
	...
	y = r1$f1 + r2$f2;
```

If the table `tbl` has an `&default` attribute, and the value of
`foo` is not in the table, _and_ the `&default` calls a function
rather than simply supplying a constant value, then perhaps that
function modifies a global record that happens to be aliased to
`r1`! (Even worse: maybe that function inserts something into a
_different_ table and _its_ `&default` function modifies such a
global!)

You might think that given this wide-ranging collection of headaches,
we'd just skip CSE, or only do it in very straightforward situations.
However, it is such a large gain - much of which occurs in
non-straightforward situations - that the optimization framework
does indeed track all of these sorts of considerations.  This is
done by a combination of AST profiling (which includes figuring
out things like identifying which aggregate types, if any, `tbl`s
`&default` attribute could alter, either directly or indirectly)
plus a bunch of careful analysis in `CSE.cc` and
`Reducer::ExprValid()` (which [documents](https://github.com/zeek/zeek/blob/9e85a0d27da6b65bb50470cc83df2d4b9bf207eb/src/script_opt/Reduce.cc#L504) a number of considerations).

### AST Idioms

The optimizer recognizes several scripting idioms and standard
script-level functions:

* Conditionals of the form `x > y ? x : y` or `x < y ? x : y` for _maximum_
or _minimum_.

* Relationals of the form `|aggr| > 0` (and variants) for testing whether
an aggregate has any elements.

* Calls to `id_string()` to convert a connection's 4-tuple to a string of
the form `%s:%d > %s:%d`. (These turn out to be an inefficient hot-spot.)

These are all converted to `ScriptOptBuiltinExpr` AST nodes to enable the
ZAM compiler to compile them to specialized instructions.

<a name="bif-properties"></a>
## BiF Properties

As mentioned above, in some contexts the optimizer needs to know various
attributes of a given BiF in order to assess any considerations involved
when a script function calls it. The interfaces for inquiring about different
attributes are in `src/script_opt/FuncInfo.h`, with the corresponding code
in `src/script_opt/FuncInfo.cc`.

The information is in fact slightly broader than just covering BiFs: it
also includes certain standard functions defined as Zeek scripts that
optimization knows how to optimize.

The various attributes of interest are:

* Completely free of side effects. Does not alter any script-level state.
(Not a concern if it modifies internal state.)

* The same, but also doesn't modify any other Zeek state, though might
have side effects such as writing to a disk file.

* Calls with the same arguments always yield the same results (_idempotency_),
if the call is made after Zeek initialization.

* The same, but holds for even if the call is made prior to Zeek initialization,
along with a promise that no errors/warnings can be generated.  The
distinction here from the previous item is important because calls to these
sorts of functions with constant arguments can be _folded_, whereas the
previous sorts of functions cannot.

* A script function known to the event engine and potentially called during
its processing.

* A script function known to ZAM and replaceable by specialized instructions.

As noted previously, these properties are maintained via a combination of
a script in `src/script_opt/ZAM/maint/` and a special BTest
(`testing/btest/opt/ZAM-bif-tracking.zeek`).

<a name="zeek-abstract-machine"></a>
## Zeek Abstract Machine

Before describing how the ZAM compiler transforms reduced, optimized
ASTs into low-level byte code, it's helpful to sketch the execution
target, i.e., just what is ultimately going to be executed.

As noted above, ZAM-optimized function bodies are represented
by `ZBody` objects, a subclass of `Stmt` AST node. The main parts of
ZAM execution concern the _frame_ that holds the values of local
variables and the _operations_ (instructions) to execute, which we
cover here in turn.


### ZAM Values and Their Management

When executing a function body without script optimization,
the Zeek interpreter uses a `Frame` object to hold a collection
of `ValPtr` smart pointers to dynamically allocated `Val` objects.
Each local variable (including function parameters) is allocated
an _offset_ in the `Frame` object, with lambda _captures_ being
dealt with via special-casing when evaluating the value associated
with a `NameExpr` AST node (each of which corresponds to either a local
variable, a capture, or a global).

The ZAM _frame_ is analogous but more streamlined: it is a low-level
C++ array (not a `std::array`) of `ZVal`s. Each `ZVal` is a union of
all of the possible low-level Zeek value types (e.g., `count`, `table` ...).
`ZVal`s differ from `ValPtr`s in three important ways: (1) they do not
requiring memory allocation/deallocation for simple types like `count`;
(2) access to their values does not incorporate type-checking, thus it's
faster (but also more dangerous); (3) by itself a given `ZVal`
is _ambiguous_ - it does not carry around any type information, and
thus that must be explicitly incorporated. The most significant implication
of this last difference is that ZAM execution needs to include explicit
memory management, rather than getting it for free as is the case
with `ValPtr`s (however `ValPtr`s can also incur overhead due to unnecessary
memory management).

In addition, internally Zeek `VectorVal`s hold their values using a
`std::vector<ZVal>`.  (This is the case regardless of whether script
optimization is in use). In some scripting contexts such vectors can be
typed as `vector of any` whereas at run-time the vector _does_ have a
concrete type. This in particular happens when a `vector` value is
initialized using an empty `vector()` constructor. Because of this
discrepancy, ZAM needs to explicitly transform such `vector of any`s
into `vector of T` where `T` is the actual type. The script interpreter
doesn't need to make this change because it always deals with the elements
of the vector as `Val` objects (which require dynamic construction from
the underlying `ZVal` union).

ZAM also needs to deal with function _parameters_ (passed into a ZAM `ZBody`
using a script-level `Frame` object holding `ValPtr`s), _globals_,
and lambda _captures_. Parameters are loaded from the frame
into a corresponding ZAM frame slot, translating the `ValPtr` to a
`ZVal`. In interpreted execution, globals and captures have their
own `ValPtr`s separate from the `Frame` object. ZAM loads these into
corresponding `ZVal` locals, and writes back their values to their
separate storage on whenever the global or capture is assigned. (This
turns out to not be common. ZAM used to have a more complex mechanism
for tracking which globals were _dirty_ and needed updating, but it
could lead to errors in complex situations where globals were separately
altered - such as via `&default` functions - so now a simple write-through
cache is used.)

If a ZAM function is potentially recursive (as revealed by AST profiling),
then its _frame_ is dynamically allocated upon execution. However, if it's
not potentially recursive (far and away the most common case), then the
frame is created _statically_, which avoids allocation/deallocation overhead.


### ZAM Instructions

Each function body is compiled into a ZAM program made up of an array
of pointers to ZAM instructions (`ZInst` objects). Instructions have
a standardized format:

* `op`
	The associated op-code. Used as the index for a
	C++ switch statement to access the specific C++ code
	associated with executing the instruction.

* `v1`, `v2`, `v3`, `v4`
	Four integer values, often referred to as _slots_.
	These are often used as indexes into the function's _frame_
	in order to access or assign to variables, but they
	can also be used as integer constants, or indices into
	auxiliary data structures. By convention, if an instruction
	assigns to a variable (very common), the variable is
	designated by the value in `v1`. In any case, slots
	are always used left-to-right, so for example if an
	instruction needs 3 integer values, `v4` will not be used
	and the others will be. In addition, for instructions
	that use slots both as frame indices and as constants,
	the frame indices are always the lefthand values, and
	the constants the later (rightward) values.

* `c`
	An associated script-level constant, expressed as a `ZVal`.
	This value is optional (since many instructions don't need
	a script-level constant); if not present, `c` is set to
	an empty `ZVal`.

* `op_type`
	Encodes how the instruction uses the various elements.
	Expressed as a `ZAMOpType` constant. For example, an
	`op_type` of `OP_VVC_I2` means that the instruction
	uses two of the slots (so `v1` and `v2`) and also the
	constant in `c`, and the second of the slots (`v2`) is
	interpreted as an integer rather than as a frame index.
	See `src/script_opt/ZAM/ZOp.h` for further description
	and a list of all of the types.
`op_type`s are used for printing out ZAM instructions
in a meaningful fashion (hugely helpful for debugging);
they are not used during normal execution.

* `t`
	An optional `TypePtr` value giving a Zeek scripting type
	associated with the instruction. This is often required
	because `ZVal` values do not include their associated
	`Type`.

* `t2`
	A second such `TypePtr` value - only rarely needed.

* `is_managed`
	An optional boolean that indicates whether the `v1` slot
	(always an assignment target, if the boolean is present)
	requires memory management.

* `aux`
	An optional pointer to _auxiliary_ information needed
	by the instruction. See the [discussion](#inst-aux) below.

* `loc`
	The source code location associated with the instruction,
	expressed as a `ZAMLocInfo` object.  These values are
	actually more complex than the `Location` objects associated
	with AST nodes, because they also include the _call graph_
	of locations leading up to the given point in the source
	code due to inlining of function calls, which allows
	disambiguating different instantiations of the same
	source code line.

Some instructions need to deal with an extensive collection of operands,
beyond what fits with the above static framework. For example, a function
call with 5 arguments cannot be expressed using just 4 slots. For these,
the `aux` field points to a `ZInstAux` object. The main use of these objects is
to hold an array of `AuxElem` objects, each of which specifies either an
integer value (usually meant to be used as a frame slot) or a constant, which
might be a low-level `ZVal` or a higher-level `ValPtr`, along with an
associated type and an indication of whether use of the element requires
memory management.

<a name="inst-aux"></a>
Auxiliary `ZInstAux` objects also provide various grab-bag fields used by
oddball instructions here-and-there. These include information for
constructing lambdas and `when` triggers, attributes, event handler names,
mappings of record fields and other information for efficient record
creation and updating, elements used for looping over tables, and the
control flow information associated with the instruction (such as whether
it's the start of a conditional or the end of a block), useful for debugging.

ZAM instructions come in two forms: `ZInst` objects, corresponding to what's
described above, and _intermediary_ `ZInstI` objects, a subclass of `ZInst`,
which use abstract branches (pointers to other `ZInstI` objects rather
than integer program-counter values) and track analysis information
such as whether the instruction is _live_, its loop depth, and how
many branches come into it. These attributes are used for [low-level
optimization](#finalizing), as described below.


## Generating ZAM Instructions

The general philosophy guiding the design of the ZAM instruction set
is to factor out as much static information as possible, meaning that
individual instructions should avoid conditional tests when the outcome
of the condition can be determined at compile time. For example,
in the interpreter the `TimesExpr` AST node for handling the "`*`"
multiplication operator checks at run-time, using an _if-else_ sequence,
whether the operands are `int`, `count`, or `double`. ZAM instead
has 3~different ZAM instructions, one for each type of operand, so
no run-time test is needed.

Actually, it has 21 different instructions for multiplication. The extra
dimensions come from (1) which of the operands is a constant (for which
there are three possibilities - none, the lefthand one, the righthand one - note that if they are _both_ constants then instead script optimization
will fold the multiplication at compile-time), (2) whether the LHS of the
operation is a direct assignment to a variable or instead an assignment
to a record field, and (3) whether its a vector multiplication (in which
case the operands are always variables).

For multiplication, there's actually no need to support both
first-operand-is-a-constant and second-operand-is-a-constant as
discussed above, since the operation is commutative and therefore could
always be written to only require one of these. However - as we'll
discuss shortly - because ZAM instructions are automatically generated
from templates, we get both flavors of one-operand-is-constant for "free".

Clearly it would be very tedious, and bug-prone, to code up all 21 possibilities by hand. Instead, ZAM uses a _templating language_ where all
that's required is to specify the particulars of a given family of
instructions, allowing the auxiliary program `gen-zam` to produce all of
the family members. For example, for multiplication the template is:

```
	binary-expr-op Times
	op-type I U D
	vector
	eval $1 * $2
```

and That's It. Here the template specifies the `Times` family of instructions.
They correspond to a binary (two-operand) expression, so `gen-zam` knows
that each instruction will take two operands and assign a result to the LHS
(always specified by the instruction's `v1` slot, as discussed above).
The next line instructs `gen-zam` to produce versions for (signed) integers,
unsigned integers, and double-precision. The third line specifies that
it should also produce versions for vectorized operation. Finally,
the fourth line gives abstract C++ code for evaluating the expression.
Here, `$1` refers to the first operand (which might be a variable given
by a frame slot, or might be a constant) and likewise `$2` the second
operand. (This expression is also used as the "kernel" for vector operations.)

From this, `gen-zam` produces instructions with the following op-codes:

```
	OP_TIMES_VCV_D
	OP_TIMES_VCV_U
	OP_TIMES_VCV_I
	OP_TIMES_VCVi_field_D
	OP_TIMES_VCVi_field_U
	OP_TIMES_VCVi_field_I
	OP_TIMES_VVC_D
	OP_TIMES_VVC_U
	OP_TIMES_VVC_I
	OP_TIMES_VVCi_field_D
	OP_TIMES_VVCi_field_U
	OP_TIMES_VVCi_field_I
	OP_TIMES_VVV_D
	OP_TIMES_VVV_U
	OP_TIMES_VVV_I
	OP_TIMES_VVVi_field_D
	OP_TIMES_VVVi_field_U
	OP_TIMES_VVVi_field_I
	OP_TIMES_VVV_vec_D
	OP_TIMES_VVV_vec_U
	OP_TIMES_VVV_vec_I
```

It also produces C++ that knows, upon encountering a `TimesExpr` AST node
(in reduced form), how to map it to a usage of the appropriate one of these instructions.

The templates processed by `gen-zam` reside in `src/script_opt/ZAM/OPs/`.
There's a [README.txt](https://github.com/zeek/zeek/blob/9e85a0d27da6b65bb50470cc83df2d4b9bf207eb/src/script_opt/ZAM/OPs/README.txt) file in that directory that describes each of
the templating language components. We'll now walk through one more
example to convey the flavor of some of the other considerations.

Here is the template used for some forms of `add` statements (add an
element to a set), where there's only a single index (so for example `add
my_set[my_ind]`, but not for `add my_set[my_ind1, my_ind2]`):

```
	op AddStmt1
	op1-read
	set-type $1
	classes VV VC  
	eval    EvalAddStmt($1, $2.ToVal(Z_TYPE))
```

It defines the `AddStmt1` family of instructions, and tells `gen-zam` that
these are simply operations (i.e., they don't have any additional information
about layout etc. such as conveyed by `binary-expr-op`). The second
line informs the ZAM low-level optimizer that these instructions do _not_
assign to their first slot (`v1`), contrary to how most instructions
work. (Note that they do _alter_ the aggregate specified by `v1`, but
that is different from assigning a new aggregate to that variable, so
the operation is "read-only" regarding the value of the aggregate.)

The next line specifies that the type that should be associated with the
instructions comes from the _second_ operand. (This looks weird, but it's
because `$$` is used for the first operand since for most instructions
that's the assignment target, so in these templates, the first _RHS_
operand is in fact the second instruction operand.)

The following line instructs `gen-zam` to produce two flavors of the
instruction, one of type `OP_VV` (two variable operands, specified by the
`v1` and `v2` slots), and one of type `OP_VC` (one variable operand, found
in `v1`, and one constant operand).

The `eval` specifies a C++ code template for which `$1` will be replaced
with the first operand, and `$2` with the second (whether it is a variable
or a constant). `Z_TYPE` is a C++ `#define` definition expanding to 
the Zeek `TypePtr` corresponding to the second operand (per the `set-type`
specification). `ToVal()` is a `ZVal` method for converting a `ZVal` to
a `ValPtr`. `EvalAddStmt` is a templating _macro_ (which is implemented
by turning it into a C++ `#define` macro). Here's its definition:

```
macro EvalAddStmt(lhs, ind)
	auto index = ind;
	bool iterators_invalidated = false;
	lhs.AsTable()->Assign(std::move(index), nullptr, true, &iterators_invalidated);
	if ( iterators_invalidated )
		WARN("possible loop/iterator invalidation");
```

`gen-zam` generates in `build/src/` a large number of C++ files, each
included for use in a different context. For the above example of `AddStmt1`,
these are:

### ZAM-OpDesc.h

This contains a description of each ZAM instruction, allowing
	reflection for identifying some forms of errors when writing
	ZAM instruction templates. Here the entries are:
```
{ OP_ADDSTMT1_VV,
	{
	"VV", 
	"",
	"EvalAddStmt(frame[z.v1], frame[z.v2].ToVal(Z_TYPE))\n" }
},       
{ OP_ADDSTMT1_VC,
	{     
	"VC",
	"",   
	"EvalAddStmt(frame[z.v1], z.c.ToVal(Z_TYPE))\n" }
},
```

These are included as part of the definition of a large _map_
	in `src/script_opt/ZAM/Validate.cc` (not yet documented).

### ZAM-MacroDesc.h

A companion file with descriptions of all of the macros used
	to define ZAM instructions. For our example, what's germane is:
```
{ "EvalAddStmt",
  "#define EvalAddStmt(lhs, ind) \\\n"
  "     auto index = ind; \\\n"    
  "     bool iterators_invalidated = false; \\\n"
  "     lhs.AsTable()->Assign(std::move(index), nullptr, true, &iterators_invalidated); \\\n"
  "     if ( iterators_invalidated ) \\\n"
  "             WARN(\"possible loop/iterator invalidation\");"
},
```

### ZAM-EvalDefs.h

The code used to execute the instruction. Incorporated into a
	(very) large switch statement in `ZBody::Exec()`. Quite straightforward
	here (and usually):

```
case OP_ADDSTMT1_VV:
	{
	EvalAddStmt(frame[z.v1], frame[z.v2].ToVal(Z_TYPE))
	}
	break;

case OP_ADDSTMT1_VC:
	{
	EvalAddStmt(frame[z.v1], z.c.ToVal(Z_TYPE))
	}
	break;
```

### ZAM-MethodDefs.h

C++ methods that the ZAM compiler calls upon encountering an appropriate
`add` statement AST node in order to convert it to ZAM code.

```
const ZAMStmt ZAMCompiler::AddStmt1VV(const NameExpr* n1, const NameExpr* n2)
	{
	ZInstI z;
	z = GenInst(OP_ADDSTMT1_VV, n1, n2);
	z.SetType(n2->GetType());
	return AddInst(z);
	}

const ZAMStmt ZAMCompiler::AddStmt1VC(const NameExpr* n, const ConstExpr* c)
	{
	ZInstI z;
	z = GenInst(OP_ADDSTMT1_VC, n, c);
	z.SetType(c->GetType());
return AddInst(z);
}
```

(These methods are declared in a separate file, `ZAM-MethodDecls.h`.)

### ZAM-Op1FlavorsDefs.h

Captures the _flavor_ of how the LHS operand is treated. Here:

```
	OP1_READ,       // OP_ADDSTMT1_VV
	OP1_READ,       // OP_ADDSTMT1_VC
```

Other values are `OP1_WRITE` (the most common), `OP1_READ_WRITE`,
and `OP1_INTERNAL`.

### ZAM-OpSideEffects.h

Tracks whether a given instruction has side effects (meaning,
even if its assignment target turns out to not be needed,
the low-level optimizer should not delete the instruction).
This is `false` for most instructions, including our example ones:

```
	false,  // OP_ADDSTMT1_VV
	false,  // OP_ADDSTMT1_VC
```

### ZAM-OpsDefs.h

Defines each op-code as part of a large C++ `enum`. Here our example
instructions are simply listed, along with all the others:

```
	OP_ADDSTMT1_VV,
	OP_ADDSTMT1_VC,
```

### ZAM-OpsNamesDefs.h

Translates op-codes to human-readable strings for debugging.

```
	case OP_ADDSTMT1_VV:    return "addstmt1-VV";
	case OP_ADDSTMT1_VC:    return "addstmt1-VC";
```

For the above example, `gen-zam` will also create an entry in
`ZAM-EvalMacros.h`:

```
#define EvalAddStmt(lhs, ind) \
	auto index = ind; \
	bool iterators_invalidated = false; \
	lhs.AsTable()->Assign(std::move(index), nullptr, true, &iterators_invalidated); \
	if ( iterators_invalidated ) \
		WARN("possible loop/iterator invalidation");
```

### Other Generated Files

While not germane for our `AddStmt1` family of instructions, `gen-zam`
also generates a large number of additional files, which we briefly describe
here:

* `ZAM-GenExprsDefsC1.h` \
	`ZAM-GenExprsDefsC2.h` \
	`ZAM-GenExprsDefsC3.h` \
	`ZAM-GenExprsDefsV.h` \
These all hold switch statements for converting `Expr` AST nodes into calls
to methods defined in `ZAM-MethodDefs.h`.  The first three apply when one
of the 1st, 2nd or 3rd expression operands (on the RHS) is a constant. The
last applies when all of the operands are variables.

* `ZAM-GenFieldsDefsC1.h` \
	`ZAM-GenFieldsDefsC2.h` \
	`ZAM-GenFieldsDefsV.h` \
Similar, but when the LHS is an assignment to a record field rather than
to a simple variable.

* `ZAM-DirectDefs.h` \
Used to override the mappings provided by the above when a special method
needs to be used rather than the default ones produced by `gen-zam`.

* `ZAM-Vec1EvalDefs.h` \
`ZAM-Vec2EvalDefs.h` \
Switch statements for evaluating 1-operand and 2-operand vector operations.

* `ZAM-Conds.h` \
Switch statements for converting relationals used in `if` statements into
their corresponding ZAM instructions.

### ZAM-AssignFlavorsDefs.h

This one is fairly involved, so we give it its own section.

Provides up to three types of information associated with an instruction
or an instruction family. For example
```
assignment_flavor[OP_CALL2_V][TYPE_DOUBLE] = OP_CALL2_V_D;
```
is used to determine, for a given function call with two arguments
(`OP_CALL2_V`), returning a type `double`, that the corresponding op-code
is `OP_CALL2_V_D`.

```
assignmentless_op[OP_CALL2_V_D] = OP_CALL2_X;
```
is used to determine that if, for such a call, the low-level optimizer
determines that the return value won't be used, then the instruction can
be translated into a `OP_CALL2_X` instruction ...

```
assignmentless_op_class[OP_CALL2_V_D] = OP_X;
```
... and if such a translation is done, then this entry indicates that the resulting
instruction has an `op_type` of `OP_X` (meaning, no variables or constants,
because all of the call information is in the `aux` field).


<a name="compile-to-zam"></a>
## Compiling To ZAM

The ZAM compiler walks the optimized, reduced AST and for each node
generates a small number (very often one) of ZAM instructions to implement
it. This process is greatly eased by the numerous _glue_ files generated
by `gen-zam`; these nearly automate compiling `Expr` nodes, and for
`Stmt` nodes often provide readily available methods.

Still, some compilation instead requires lower-level generation of individual
`ZInstI` instructions. Much of this is eased by a set of `GenInst()` methods
defined in `src/script_opt/ZAM/Gen-Inst.h`. These take `NameExpr` and
`ConstExpr` nodes and automatically map them to instruction slots corresponding
to ZAM frame positions, or the `c` constant associated with ZAM instructions.

The largest structural changes concern control flow: ASTs have notions of
inner and outer statement blocks, and abstract constructs such as `for`
loops and `switch` statements, which don't readily fit into low-level byte
code execution. The compiler turns such constructs into abstract `go-to`
statements that work by adjusting the program counter used during ZAM
execution.

To help with debugging these transformations, the compilation process
associated _control flow types_ with ZAM instructions. These include:

* `CFT_IF`
	The start of an _if_ statement (i.e., just before computing
	whether to branch).

* `CFT_ELSE`
	The start of the _else_ branch of an _if_ statement.

* `CFT_BLOCK_END`
	The given instruction marks the end of a block of statements.

* `CFT_LOOP`
	The start of a `for` loop. This generally comes _earlier_ than the
	loop's condition, because some instructions must be executed to
	initialize the loop.

* `CFT_LOOP_COND`
	The instruction that tests the condition of whether to continue
	the loop.

* `CFT_LOOP_END`
	The end of the loop's body.

* `CFT_BREAK`
	The given branch corresponds to a `break` statement.

* `CFT_NEXT`
	The given branch corresponds to a `next` statement.

* `CFT_DEFAULT`
	The given statement starts the `default` case of a switch statement.

* `CFT_INLINED_RETURN`
	The given statement marks the return from an inlined function call.

Note that some of these attributes might apply _multiple times_ for a given
instruction. For example, the same instruction might mark the end of more
than one statement block (`CFT_BLOCK_END`). Because of this consideration,
control flow information records not just the presence of a given type of
control flow but also a count regarding how many instances it represents.

This stage of compilation introduces one significant optimization: replacement
of calls to certain Zeek BiFs with specialized instructions. Doing so can
be a significant performance win for BiFs that either are called frequently
but don't take too long to execute (in which case the win is by eliminating
function call and value conversion overhead); or that have internal overhead
due to needing to dynamically assess the types of their arguments, whereas
for a given call ZAM already knows what these are statically.

When encountering a call, the `IsZAM_BuiltIn()` predicate returns
true if it corresponds to a BiF that ZAM can replace (and it goes ahead
with the replacement). An analogous call `IsZAM_BuiltInCond()` is
used for calls that are part of conditional tests (`if` statements or
`while` tests).

At this point in ZAM's evolution there are enough such BiFs (about three
dozen) that it helps to both isolate the code for dealing with them (see
`src/script_opt/ZAM/BuiltIn.cc`) and define a number of abstractions to
make adding new ones easier. For example, using these the entire code
necessary to replace the `Files::__analyzer_enabled` BiF is:

```
SimpleZBI ae_ZBI{"Files::__analyzer_enabled", OP_ANALYZER_ENABLED_VC, OP_ANALYZER_ENABLED_VV};
```

plus the following ZAM instruction template:
```
internal-op Analyzer-Enabled
classes VV VC       
op-types I X
eval    $$ = ZAM::file_mgr_analyzer_enabled($1.ToVal(Z_TYPE)->AsEnumVal());
```

For the first part of this, a `SimpleZBI` is a _ZAM BuiltIn_ (ZBI) that
takes either no arguments or only one argument. The initializer above uses
a throw-away name (`ae_ZBI`) to associate the name of the BiF with two ZAM
instructions, one taking a constant argument and one taking a variable
argument; both return a value (the initial `V` of the `classes`).

Additional subclasses support BiFs taking more arguments, and two complex
BiF substitutions: a replacement for `sort()` that knows to skip the
replacement if the arguments are invalid (something that the BiF only
determines at run-time) and streamlines the very common case of the argument being a vector with only 0 or 1 elements; and a replacement for `cat()` that removes the
need for that function to analyze the types of its arguments at run-time.
Regarding this latter, a good target for the future would be to replace
calls to the `fmt()` BiF, as it has similar run-time dispatch. `fmt()` has
the added complexity of needing to support different format strings; perhaps
the replacement could initially restrict its usage to simpler formats.

<a name="finalizing"></a>
## Finalizing the ZAM Program

Once the compiler has converted the AST to a set of intermediary ZAM
instructions, two more steps remain: (1) _concretizing_ the instructions
into a final ZAM program, and (2) _optimizing_ the resulting low-level code.

Concretization is straightforward: branches that were initially represented
in abstract terms (pointers to instructions), including loops, `next` and
`break` statements, are now changed into branches to absolute locations
in the program (i.e., integer offsets into the array of instructions).
This includes the tables used for `switch` statements.

In addition, when doing so the compiler also computes _loop levels_,
i.e., the degree of nested looping present for each instruction. These
are used by the low-level optimizer to track the [usage range of frame
variables](#frame-lifetime) (see below).

The low-level optimization involves a number of steps:

- ZAM computes how many branches target each instruction (used for
deciding whether code is "dead").

- All "NOP" instructions are "killed" (marked as not [_live_](#live-inst); see below). These can be introduced
during compilation for uses such as placeholders for loop branches.

- The optimizer then repeatedly makes passes over the ZAM program
until a pass no longer introduces any change. Each pass covers the
following:
<a name="live-inst"></a>
  - For any _live_ instruction, checking whether it branches to the next live
instruction, and if so, killing the branch,
unless it has side effects (which loop iterations do).
  - If the instruction does not continue to its successor (e.g., an
unconditional branch elsewhere), and the successor doesn't have any labels
(it's not a branch target), then the successor is killed.
  - Any branch (including conditional) that targets an unconditional branch
can be (repeatedly) altered to instead branch to the target's own target.
<a name="frame-lifetime"></a>
  - For each frame variable, ZAM computes it's _lifetime_: when it is assigned
and when it is last used. This computation incorporates the _loop levels_
mentioned above in order to correctly recognize that a frame variable's
lifetime might come _before_ its first assignment if it's inside a loop.
The logic regarding assignment is somewhat involved because it needs to
track instructions that don't follow the common assign-to-slot style,
and similarly for usage, since for some instructions the frame variables
it uses are in the _auxiliary_ information rather than being expressed
directly in the instruction's slots.
  - ZAM kills any variable assignments
for which the variable isn't subsequently used (unless the instruction
has side effects, in which case we transform the instruction into its
complementary form that doesn't do an assignment).
  - ZAM removes loads of globals or captures in straight-line
code (no inbound branches) for which the same load has occurred earlier.

- After an iteration over the above finally does not result in any changes, the optimizer
makes a pass over the program to determine which frame variables have lifetimes
that do not overlap. These are then candidates for _doubling up_, i.e., sharing a frame slot. This step is a vital optimization
as without it, due to aggressive inlining, a ZAM program's frame can grow
very large, requiring much more time to initialize and manage.

- The one nuance with doubling-up is that sharing is not done across a mix
of frame variables that are _managed_ (use reference counting, e.g. `table` values) and _unmanaged_ (e.g., `count` values), to ensure consistent memory
management for doubled-up slots across their different uses.

- This pass also identifies Zeek scripting globals (which temporarily reside
in frame variables) that aren't used, and removes them.

- At this point, the instructions all need to have their slots updated to
reflect the frame sharing. Similarly to the previous identification of frame
variable lifetimes, this needs to be done with sensitivity to atypical
instructions that don't assign to the first slot and/or have frame variable
offsets in their _auxiliary_ information.

- As a final step, the `Frame` size associated with the function is reduced
to just the number of parameters used when calling it. This makes the
invocation of compiled functions more efficient because they don't need
to allocate large `Frame` object arrays that would for the most part would
go unused.

Whether or not optimization is run, the last compilation step is to translate
the (live) abstract `ZInstI` instructions to concrete `ZInst` instructions
to form the final program, which is used to construct a `ZBody` object
that replaces the `Stmt` AST object that originally represented the function's
body.

Once done with the compilation, the memory associated with the ASTs is
reclaimed, to aid in reducing the memory footprint of ZAM-compiled scripts.
(An exception is when using ZAM's fine-grained profiling, where some of
the original state is kept in order to loop over functions to generate
their profiles.)

<a name="execution"></a>
## Execution

Functions with `ZBody` objects for their bodies look the same, externally,
as those with `Stmt` object bodies. This means that ZAM-optimized scripts
are fully interoperable with non-ZAM-optimized scripts (and with calls made
up from the event engine).

Interpreted scripts have a `Frame` object that holds a number of `ValPtr`
objects pointing to the values of the script's local variables, including
its function parameters. For ZAM-optimized scripts, the local variables
are managed separately in an array of `ZVal` objects, so their `Frame`
objects just have slots for the function parameters (necessary for
interoperability). The first ZAM instructions of a ZAM program then
load the parameters from the `Frame` and store their `ZVal` representation
as local variables.

Prior to executing the ZAM program, `ZBody::Exec` creates a `ZBodyStateManager`
state management object.  This object provides memory management for all
of the `ZVal` locals that require it; because it does so via its destructor,
memory management occurs even if execution is aborted via a C++ exception.
(It also manages state for some objects used during execution - in particular,
tracking the values used for `for` loop iterations.)

Execution proceeds using a program counter that indexes into the collection
of ZAM instructions that comprise the program. Executing a single instruction
involves switching on its op-code into a large collection of cases, one
per distinct operation.  After most instructions, the PC is incremented
to fetch the next instruction, but branches instead assign new values
to it. Execution finishes when the PC exceeds the number of available
instructions. At that point, all that remains is to construct the return
value (as a `ValPtr`), if any.

<a name="btests"></a>
## BTests

The BTest `-a zam` alternative runs the CI test suite using ZAM optimization.
Most of the tests run producing identical results to ordinary interpreted execution. Those that vary, requiring
their own `Baseline.zam/` baseline, usually differ simply in terms of
error messages, or execution information such as backtraces. In addition, the
`testing/btest/opt/` directory has a number of tests specifically designed
for script optimization, including a few for catching regressions of
bugs now fixed.

<a name="trouble"></a>
## Trouble-shooting

To diagnose a ZAM problem, the first step is to construct as simple of
a reproducer as possible. There are several tools for doing so:

* Using `--optimize-file=xyz` will confine optimization to just scripts
whose filename matches the regular expression _xyz_. (The regular expression
is unanchored by default, but you can use `^` and `$` to anchor it if
need be.) Multiple instances of this argument will expand the optimization
to scripts matching any of the corresponding regular expressions.

* Using `--optimize-func=xyz` will confine optimization to functions
(or events or hooks) whose name matches _xyz_. (Here the regular expression
_is_ anchored, though you can override that by adding `.*` to either end.
For example, you can use `--optimize-func=Module::.*` to match every function in the
`Module` namespace.)

* True functions (i.e., not events or hooks) often are _fully optimized away_
by the inliner, which can make pinpointing issues with them difficult.
You can turn off the inliner using `-O no-inline`.

* In addition, as noted above, ZAM can _coalesce_ multiple event handlers
for the same event into a single body, which can make it difficult to
isolate issues in just one particular handler. You can turn this off using
`-O no-event-handler-coalescence`.

* You can run the interpreter on the reduced AST by using just `-O xform`
(no `-O ZAM`). If the problem already manifests at that point, then it
relates to the reduction process.

* You can inspect the AST-level transformations ZAM does using `-O dump-xform`.

* If `-O xform` doesn't cause the problem to manifest, you can try
`-O optimize-AST` instead, which also employs the AST-level optimizer,
though still executes the result using the interpreter.

* Bugs arising from the AST-level optimizer sometimes are due to mistakes
in how ZAM computes which variables are defined and used at which points
in a function. You can dump information about this using `-O dump-uds`.

* If the optimized AST doesn't manifest the problem, you can use
`-O gen-ZAM-code` to generate ZAM code but without using the AST optimizer
nor ZAM's low-level optimizer.

* You can generate ZAM code that uses the AST optimizer but not ZAM's
low-level optimizer via `-O no-ZAM-opt`.

* The analog to `-O dump-xform` for ZAM code (rather than for AST
transformations) is `-O dump-ZAM`. This includes a bunch of intermediary
stages. If you want to inspect just the final code, use `-O dump-final-ZAM`.

* When using the debugger to analyze ZAM compilation, or the resulting
execution, one very handy function is `obj_desc()`. It takes a pointer to
a Zeek `Obj` and returns its string description. (Note that it requires
bare pointers, so if you have an `IntrusivePtr` - as is often the case -
you can invoke it using `print obj_desc(my_intrusive_ptr.ptr_)`.)

* When rebuilding Zeek due to trying to fix ZAM issues, note that if you
change any ZAM instructions, you sometimes need to compile twice.
Ninja (and maybe Make) misses some of the dependencies, which are subtle
since they come from use of dynamically generated files.
