<h1 align="center">

Script Optimization: Internals

</h1><h4 align="center">

[_Overview_](#overview) -
[_Inlining_](#inlining) -
[_Transforming to Reduced Form_](#Transforming-to-Reduced-Forms) -
[_Optimizing Reduced Form_](#Optimizing-Reduced-Forms) -
[_Removing Unused Locals_](#Removing-Unused-Locals) -
[_Compiling to ZAM_](#Compiling-to-ZAM) -
[_Templating_](#Templating) -
[_Replacing BiFs_](#Replacing-BiFs) -
[_Optimizing ZAM Code_](#Optimizing-ZAM-Code) -
[_Finalizing ZAM Code_](#Finalizing-ZAM-Code) -
[_Saving ZAM Function Bodies_](#Saving-ZAM-Function-Bodies) -
[_Executing ZAM Functions_](#Executing-ZAM-Functions) -
[_Representing Zeek Script Values_](#Representing-Zeek-Script-Values) -
[_New Source Files_](#New-Source-Files)

</h4>


<br>

Overview
--------

Zeek _script optimization_ employs a series of techniques aiming to execute
Zeek scripts with higher performance.  The heart of the approach is to
compile Zeek scripts, as represented by _Abstract Syntax Trees_ consisting
of `Stmt` and `Expr` Objects, into a low-level form that can generally be
executed more efficiently.  This target form is termed `ZAM` (_Zeek Abstract
Machine_).

Script optimization applies to Zeek functions, hooks, and event handlers.
It does not currently apply to top-level statements or functions provided
in contexts such as `&..._expire` handlers.

In high-level terms, optimization proceeds in a set of stages:

1. Once all scripts have been parsed as usual, for each function/event/hook
body the optimizer first looks for an associated
[`.ZAM` file](#Saving-ZAM-Function-Bodies) holding the results from previous
compilation.  If present, it loads the compiled form of the function body
from there, skips the remaining stages, and proceeds on to the next function.

1. Otherwise, the optimizer recursively [inlines](#Inlining) any calls
made by functions/events/hooks to script-level functions.

1. Function bodies are [transformed](#Transforming-To-Reduced-Forms) to a
"reduced" representation for which every expression has a standard,
simplified form.  This form can still be executed by the Zeek interpreter.

1. For each function body, the optimizer
[makes an optimizing pass](#Optimizing-Reduced-Forms) over its reduced
representation to eliminate redundant code, some of which gets introduced
during the transformation step and some of which may have been present in
the original script.  Again this form remains executable by the interpreter.

1. The optimizer [removes unused locals](#Removing-Unused-Locals), an
iterative process because each removal can lead to identifying additional
locals now no longer needed.

1. The function body is then [compiled](#Compiling-to-ZAM) to a series of
"intermediary" `ZAM` instructions.  At this stage, each script variable
corresponds to a distinct "frame" location during ZAM execution, and
branches are expressed in relative/abstract terms.  (This process also
includes recognizing certain Zeek built-in functions and substituting
customized ZAM instructions for calls to them.)  ZAM instructions are
specified using a [templating language](#Templating), and some of them
[replacing BiFs](#Replacing-BiFs).

1. The optimizer performs a [low-level pass](#Optimizing-ZAM-Code) over
the resulting `ZAM` code, repeatedly removing redundancies and dead code,
collapsing sequences of branches, and identifying variables that can share
the same frame location because their lifetimes do not overlap.

1. The optimizer [generates](#Finalizing-ZAM-Code) a corresponding series
of "concrete" `ZAM` instructions from the intermediary ones, including a
compressed frame for storing local variables at run-time.  This final body
of `ZAM` instructions (a `ZBody` object, derived from `Stmt`) replaces the
original function body.

1. The optimizer
[writes a representation of the compiled function body](#Saving-ZAM-Function-Bodies)
to a corresponding `.ZAM` file to avoid the need to compile the function
in the future.  Prior to running through the above stages, the optimizer
first checks for the presence of such a file.  If found, the steps outlined
here skipped, and instead the file is parsed to recover the `ZAM` function
body.

1. During [execution](#Executing-ZAM-Functions) of the scripts, calling a
compiled function/hook/event handler proceeds as it currently does, with
arguments pushed onto the interpreter's stack frame, followed by invocation
of the function body's `Exec()` method.  For a `ZBody` statement, this
method iterates over the corresponding `ZAM` instructions, rather than
recursively interpreting `Stmt`/`Expr` objects.

These steps are driven via the `analyze_scripts()` function (in `ScriptAnaly.h`
/ `ScriptAnaly.cc`), which `main()` calls after parsing all of the scripts.

Finally,
efficient script execution also entails changing elements of the
[underlying representation of Zeek script values](#Representing-Zeek-Script-Values).

Implementing the above led to the introduction of
[numerous new source files](#New-Source-Files).

<br>


Inlining
--------

Inlining function call bodies provides two major benefits: (1) for compiled
code, it avoids the overhead involved in invoking the function, and (2)
it enables optimizations - both high-level, such as constant propagation
if one of the arguments in a call is a constant, and low-level, such as
doubling up frame storage (which saves both space and time).

Inlining is an AST-to-AST transformation.  That is, the result can still
be executed by Zeek's interpreter.  However, in practice, using only
inlining and not compilation to ZAM provides little benefit: the interpreter
still does work somewhat equivalent to what's required to invoke a function,
and lacks any optimizations to leverage for the second advantage mentioned
above.

The implementation uses the following:

* The `Inliner` class, defined in `Inline.h` and `Inline.cc`.

* A new `InlineExpr` expression replaces the original function call.  When
evaluated, `InlineExpr` objects bind the values of the expressions associated
with the function arguments to the parameters in the original function
body.  They then execute the function body and yield whatever value is
produced by executing the `return` statement in the original function.

* A new `Duplicate()` method for statements and expressions facilitates the
creation of a complete copy of the original function body.  We need to use
a copy rather than the original since the original might be inlined in
multiple places, and each of those has to be distinct so that changes made
to the AST, or information associated with AST nodes, remain confined to
the inlined instance.

* The `Frame` class is extended to have the notion of an "offset", so that
the local variables in the inlined function body don't clash with those
of the caller.  Execution of an `InlineExpr` temporarily increments the
current offset so that the original offsets associated with inlined local
variables remain valid (and so that the caller's locals are inaccessible).
As this is done in relative terms, inlined functions that themselves contain
inlined functions will execute correctly.  Note that this also requires
ensuring that the caller's frame size is increased to reflect the maximum
needed to accommodate any chain of inlined functions.

* For compilation, a new `CatchReturn` statement has the semantics of
executing a series of statements and assigning the associated return value
to a given temporary variable.  This statement is required (rather than
using `InlineExpr`) because of the need to transform all expressions to
[reduced form](#Transforming-To-Reduced-Forms).  To get rid of the need
for adjusting frame offsets, when creating such statements all of the local
variables in the inlined function are renamed to unique internal names.
Doing so both allows for keeping offsets fixed at run-time, as well as
doubling up frame slots for those locals with other non-overlapping locals.

Inlining is only considered for regular Zeek script functions.  The inliner
ignores `hook`s and `event` handlers.  In principle, `hook`s could be
inlined, taking care to preserve the execution ordering and logic.  Likewise,
`event` handlers with multiple handler bodies could be collapsed into a
single body, but this isn't currently done.

The inliner examines the full set of function bodies to identify any
instances of either direct or indirect recursions.  (It does this using a
`ProfileFunc` traversal object, which gathers meta-data about function
bodies; see `ProfileFunc.h` and `ProfileFunc.cc`.) Such functions are
flagged as ineligible for inlining, though in principle they could be
"unrolled" to a limited degree similarly to unrolling loops (which the
optimizer also currently does not do), and instances of "tail recursion"
could be converted to loops.


The inliner also won't inline any function that includes a "lambda" expression or a `when` statement, since the compiler currently won't compile such functions.

<br>


Transforming To Reduced Forms
--------

This step rewrites each function/hook/event handler body to a simplified
form where every expression is either a "singleton", meaning a variable
name or a constant; or an operator for which every operand is a singleton.
To do so, the optimizer introduces temporary variables to hold intermediary
values.

Expressions appearing statements are in general reduced to singletons,
although in a few cases they are left as operators with singleton operands,
to facilitate generating more efficient code.

Here's a simple example.  For the script
```
function bar(): count
        {
        local a = 3;
        local b = 5;
        local c = 7;

        return a*b + c + 1;
        }
```
will be transformed to the equivalent of
```
function bar(): count
        {
        local a = 3;
        local b = 5;
        local c = 7;

        local #0 = a * b;
        local #1 = #0 + c;
        local #2 = #1 + 1;

        return #2;
        }
```

The transformation process also implements a range of AST optimizations
and constant folding.  Most of these are conceptually simple, such as
transforming `x + 0` to `x`, or `y - y` to `0`, or
```
if ( ! x )
    s1;
else
    s2;
```
to
```
if ( x )
    s2;
else
    s1;
```
Some are more involved, such as rewriting
`/foo/ in x || /bar/ in x` to `/(foo)|(bar)/ in x`.

These might seem hardly worth the effort, but it turns out that the overall
reduction process can both introduce new instances of these, and also
surface existing instances that aren't obvious to the script writer.

Transformation is implemented by recursively traversing the function body
by calling each AST node's (new) `Reduce()` method.  (For `Stmt` classes,
this method does some generic processing and then calls a new `DoReduce()`
method.)  The traversal is done using a `Reducer` object, defined in
`Reduce.h` and `Reduce.cc`.  Another new method, `IsReduced()`, returns
true if the node is already in a fully reduced form.  There are also a
number of related methods for controlling the depth of the reduction process
(for example, whether an expression is reduced all the way to a singleton,
or to an operator with singleton operands).

The interpreter can still execute the reduced form.  In general, it will
perform worse than the original AST because of the many assignments to
temporary variables.

<br>


Optimizing Reduced Forms
--------

After the initial transformation of the function body to reduced form, the
optimizer makes a second pass over the AST to identify _aliasing_ and
_common subexpressions_ (CSEs), and to perform _constant propagation_.

Aliasing refers to determining that two local variables track the same
exact value, and thus we can eliminate one of them and replace any references
to it with the other.  The reduction process often introduces such aliasing,
so for efficiency it's important to identify and eliminate it.

CSE refers to determining that the computation of an subexpression
(e.g., `x + 3`) can be replaced using a variable whose value reflects an
earlier computation of the same subexpression.  CSE is more general than
aliasing, because it addresses identifying _different_ instances of a
subexpression that can be safely doubled up, whereas aliasing identifies
locals assign to the _same_ instance.  We need an explicit dealiasing step,
however, because without it some expressions that are in fact the same
might not appear to be.  For example, consider:
```
    if ( x + 3 > z && y?$foo && x + 3 > y$foo ) ...
```
The reduced form of this might look like:
```
    #0 = x + 3;
    if ( #0 > z )
        {
        #1 = y?$foo;
        if ( #1 )
            {
            #2 = x + 3;
            #3 = y$foo;
            if ( #2 > #3 )
                ...
```
(It actually looks different, but the distinction doesn't matter for this
example.) Here, `#0` and `#2` compute the same value, so we can remove
`#2 = x + 3;` and change its subsequent use to be `if ( #0 > #3 )`.

It can be subtle, however, determining whether two instances of a subexpression
will indeed always reflect the same value.  For example, if the conditional
had been:
```
    if ( x + 3 > z && ++x < y$bar && x + 3 > y$foo ) ...
```
then the second instance of `x + 3` in fact represents a different value
than the first one.  More generally, one can imagine the first instance
and the second being separated by more lengthy code logic that _might_
change `x`'s value or might not, for example:
```
    x = bar();
    if ( x + 3 > z )
        {
        if ( foo() )
            x = x + 2;
        ...
        y = y * (x + 3);
	}
```
For the optimizer to determine whether it's "safe" (correct) to substitute
an instance of a CSE with a previously computed value, it needs to track
the _Reaching Definitions_ (RDs) associated with each variable.  RDs
associate with every node in the AST the set of all variable definitions
(assignments) whose value could potentially reach that node.  For the
example above, the node at the end for `(x + 3)` will have, for variable
`x`, RDs  that include both the `x = bar();` node at the top, and the `x
= x + 2;` node in the second conditional.

The optimizer can tell that it's unsafe to reuse at `(x + 3)` the temporary
that holds the first `x + 3` value because the RDs for `x` at the two
instances of the subexpression differ, and thus there's a code path where
at the second instance, `x`'s value may not be the same as held in the
temporary.

Several subtle problems arise when determining RDs, and unfortunately any
errors can lead to incorrect optimizations that produce incorrect values
that are difficult to debug.  (You can run script optimization with this
step turned off using `-O xform -O compile -O inline`, leaving out
`-O xform-opt`.  `-O all` turns on all four of these.)

The optimizer computes RDs by traversing the AST using an `RD_Decorate`
object, defined in `GenRDs.h` and `GenRDs.cc`.  The `RD_Decorate` class
in turn relies on a set of additional classes to track various data
structures; these are defined in the following source files:
```
DefItem.h DefItem.cc
DefPoint.h
DefSetsMgr.h DefSetsMgr.cc
ReachingDefs.h ReachingDefs.cc
```

What's been described so far are "maximal" RDs, i.e., at each point in the
function which definitions for a given variable could _possibly_ reach
that location.  The optimizer also calculates "minimal" RDs, i.e., at each
point in the function is a given variable _guaranteed_ to have a value.
Tracking minimal RDs enables the optimizer to flag at compile time variables
that will be accessed even though they might not have been set (reported
using the `-u` option).  In addition, the internal machinery for tracking
RDs works not only for variables but also for fields in record values,
enabling the optimizer to report at compile time accesses to record fields
that might not be set.  Such accesses are reported using the `-uu` option.
The optimizer omits this analysis for the simpler usual `-u` option because
it is computationally expensive (and finds many potential problems in the
base scripts, though of the ones I've inspected, in practice additional
logic protects the access).

The final optimization functionality at this stage concerns _constant
propagation_.  Here, if a variable is assigned to a constant value, and
at a subsequent usage of the variable that assignment is the only RD, then
the optimizer replaces the use of the variable with the constant.  If this
results in an expression having constant operands, then the optimizer folds
the expression to a single constant.  As with the other transformations,
applying this optimization can in turn introduce further optimization
opportunities.

After the basic [reduction phase](#Transforming-To-Reduced-Forms), the
optimizer makes a second `Reduce()` pass over the function body applying
the above optimizations and transformations.  The result remains an AST
executable by the interpreter.  Experience finds that the gains from
optimizing tend to be useful but not striking, and thus interpreting the
transformed-and-optimized AST generally does not yield an appreciable gain
over executing the original AST.

<br>


Removing Unused Locals
--------

The transformation process can generate a large number of assignments to
temporary variables, not all of which get removed by the preceding stage.
To systematically find these, the optimizer computes _Usage Definitions_
("_UseDefs_"), essentially the inverse of RDs: for each variable definition
(assignment), noting whether that definition is subsequently used.

UseDefs are computed by traversing through the function body _backwards_.
The very final statement has no usages, or might have a single value if a
(reduced) `return` statement returns a value.  Working backwards from there
(and taking care to correctly propagate information across loops), the
optimizer builds up a list of usages.  Upon encountering a variable
definition, it can then determine whether that definition is indeed
subsequently used.

After computing the UseDefs, the optimizer makes another `Reduce()` pass
over the function body, removing assignments for any unused variables,
taking care to leave in computation of the expression to which the unused
variable was assigned if that expression has side effects.  The process
then repeats, computing new UseDefs and removing any unused variables those
surface, as long as a given pass yields results in additional trimming.

Structurally, the optimizer implements this using a `UseDefs` object,
defined in `UseDefs.h`/`UseDefs.cc`.

Finally, computing UseDefs also enables identifying local variables (which
are not temporaries introduced by the optimizer) that have values assigned
to them but don't wind up being subsequently used.  The `-u` option turns
on this reporting.


Compiling to ZAM
--------

The optimizer transforms the modified AST to a ZAM function body by
instantiating a `ZAM` object, which traverses the AST using a new `Compile()`
method.  The `ZAM` class, defined in `ZAM.h` and (mainly) in `ZAM.cc`, is
derived from an abstract `Compiler` class, defined in `Compile.h` (and a
trivial `Compile.cc`).  The `Compile()` method for `Stmt`s and `Expr`s
uses the `Compiler` class rather than the `ZAM` class in an attempt to
keep the compilation process from being fundamentally tied to the specifics
of the `ZAM` class.  This should help if in the future we decide to implement
a different compilation target, such as C++ or LLVM.

Ultimately, compilation produces a `ZBody` object (defined in
`ZBody.h`/`ZBody.cc`). The corresponding class is derived from `Stmt`, and
thus the `ZBody` object can fully replace the current function body (i.e.,
the AST).  `ZBody`'s include an array of ZAM instructions (`ZInst`s), as
defined in `ZInst.h`/`ZInst.cc`.

However, the initial compilation target is to produce a vector of
_intermediary_ ZAM instructions (`ZInstI`s, derived from `ZInst` and defined
in the same files).  `ZInstI` instructions include information only needed
during compilation, and, in addition, use abstract branch targets rather
than concrete ones, to enable a range of
[low-level optimizations](#Optimizing-ZAM-Code).  At this stage, each local
variable or temporary (and any additional temporaries introduced in the
compilation process) resides in its own _frame_ location ("slot")..

In basic terms, `ZInst` (and thus `ZInstI`) instructions have a number of
fields:

* `op`: operation type.  Example: `OP_NEGATE_VV_D`, which is an operation
to negate a frame slot, whose type is `double`, and put the result into
another frame slot.

* `v1`, `v2`, `v3`, `v4`: up to four integer "values" associated with the
instruction.  Usually, these are frame slot offsets, but in some cases
they have other interpretations.  If the operation computes a value, the
result is always stored in the frame slot specified by `v1`.

* `c`: a constant associated with the operation, if any, using the optimizer's
[internal representation for values](#Representing-Zeek-Script-Values).

* `t`: a pointer to a `BroType` object associated with the instruction.
In most cases, this gives the type of the `c` constant, if any.

* `loc`: a pointer to the `Location` object associated with the AST node
that was compiled into this instruction.

* `is_managed`: a boolean indicating whether the value assigned by this
instruction has a "managed" (reference-counted) type.

There are some additional fields used for some uncommon cases, but the
above captures the gist of it.

Templating
--------

Much of the compilation process is implemented in a _declarative_ fashion
rather than hand-crafting methods for every possible combination of
statements, expressions, and expression operand types.  The basic model
is that a reduced AST statement will correspond for the most part to a ZAM
instruction, or perhaps a few ZAM instructions for more complicated
statements.  Each ZAM instruction has "flavors" depending on operand types
and which operand (if any) is a constant.  A ZAM instruction also has
corresponding C++ code to implement it.

All of this is expressed using `ZAM-Ops.in`, which contains templates of
ZAM instructions, and `gen-compiler-templates.sh`, a large program
(written in `awk`) that reads in the templates and produces a bevy of C++
files that different source files `#include` at various points.

The templating language is fairly involved, but here we provide some
examples to give the flavor.

First, here is the specification of how to handle the negation (`-`)
operator, i.e., an `Expr` node with a tag of `EXPR_NEGATE`:
```
unary-expr-op Negate
op-type I D
vector
eval -$1
```
The first line specifies a unary expression operator tied to the `EXPR_NEGATE`
tag.  On line 2, `op-type` specifies that this operator should have flavors
for both `int` and `double` internal types, and line 3 says that the
templater should also generate code for vectorized versions of those.  The
final line states that to evaluate the operand, use the C++ `-` operator
applied to the first (and only, in this case) operand.  As with all
expressions, the result is always assigned to the `v1` frame slot, so that
isn't explicitly mentioned here.

From this simple 4-line specification, the templater generates 12 separate
operations (for combinations of `int`/`double`, direct assignment /
assignment to record field, vectorized / not vectorized
[doesn't apply to field assignments], and variable operand / constant
operand).  Those operations then populate
_thirteen_ C++ files for inclusion, which we sketch here (with light
formatting edits for clarity):

`CompilerOpsExprsDefsV.h`: case statement for tying the `Expr` object to
the underlying compilation in usual case where the operand is a variable:
```
case EXPR_NEGATE:       
    if ( rt->Tag() == TYPE_VECTOR )
        return c->NegateVV_vec(lhs, r1->AsNameExpr());
    else
        return c->NegateVV(lhs, r1->AsNameExpr());
```

`CompilerOpsFieldsDefsV.h`: same but for where it's an
assignment-to-a-record-field, and the operand is a variable:
```
case EXPR_NEGATE:
    return c->NegateVV_field(lhs, r1->AsNameExpr(), field);
```

`CompilerOpsExprsDefsC1.h`: same, but the operand is a constant (not germane
for unary operations, since this will be folded, but germane for binary
operations):
```
case EXPR_NEGATE:
    if ( rt->Tag() == TYPE_VECTOR )
        return c->NegateVC_vec(lhs, r1->AsConstExpr());
    else
        return c->NegateVC(lhs, r1->AsConstExpr());
```

`CompilerOpsFieldsDefsC1.h`: same, but when it's an assignment to a record
field:
```
case EXPR_NEGATE:
    return c->NegateVC_field(lhs, r1->AsConstExpr(), field);
```

`CompilerBaseDefs.h`: abstract methods for the `Compiler` class to enable
compiling of this instruction:
```
virtual const CompiledStmt NegateVC(const NameExpr* n, const ConstExpr* c) = 0;
virtual const CompiledStmt NegateVC_field(const NameExpr* n, const ConstExpr* c, int i) = 0;
virtual const CompiledStmt NegateVC_vec(const NameExpr* n, const ConstExpr* c) = 0;
virtual const CompiledStmt NegateVV(const NameExpr* n1, const NameExpr* n2) = 0;
virtual const CompiledStmt NegateVV_field(const NameExpr* n1, const NameExpr* n2, int i) = 0;
virtual const CompiledStmt NegateVV_vec(const NameExpr* n1, const NameExpr* n2) = 0;
```

`ZAM-SubDefs.h`: corresponding `ZAM` subclass method declarations associated
with compiling the given expression:
```
const CompiledStmt NegateVC(const NameExpr* n, const ConstExpr* c) override;
const CompiledStmt NegateVC_field(const NameExpr* n, const ConstExpr* c, int i) override;
const CompiledStmt NegateVC_vec(const NameExpr* n, const ConstExpr* c) override;
const CompiledStmt NegateVV(const NameExpr* n1, const NameExpr* n2) override;   
const CompiledStmt NegateVV_field(const NameExpr* n1, const NameExpr* n2, int i) override;
const CompiledStmt NegateVV_vec(const NameExpr* n1, const NameExpr* n2) override;
```

`ZAM-OpsMethodsDefs.h`: implementations for those 6 methods.  Here's one
example:
```
const CompiledStmt ZAM::NegateVV(const NameExpr* n1, const NameExpr* n2)
    {
    ZInstI z;
    auto t = n1->Type().get();
    auto tag = t->Tag();
    auto i_t = t->InternalType();
    if ( i_t == TYPE_INTERNAL_DOUBLE )
        z = GenInst(this, OP_NEGATE_VV_D, n1, n2);
    else if ( i_t == TYPE_INTERNAL_INT )
        z = GenInst(this, OP_NEGATE_VV_I, n1, n2);
    else
        reporter->InternalError("bad internal type");
    return AddInst(z);
    }
```

`ZAM-OpsDefs.h`: initializations for the `enum` type definition all of the
instruction operators.  Here's the full list generated for the above
specification:
```
OP_NEGATE_VC_D,
OP_NEGATE_VC_D_field,
OP_NEGATE_VC_D_vec,
OP_NEGATE_VC_I,
OP_NEGATE_VC_I_field,
OP_NEGATE_VC_I_vec,
OP_NEGATE_VV_D,
OP_NEGATE_VV_D_field,
OP_NEGATE_VV_D_vec,
OP_NEGATE_VV_I,
OP_NEGATE_VV_I_field,
OP_NEGATE_VV_I_vec,
```

`ZAM-OpsNamesDefs.h`: cases for a switch statement on `op` that maps the
instruction's internal operator value to a human readable string.  Here's
an example of one of the 12 cases generated:
```
case OP_NEGATE_VC_I:    return "negate-VC-I";
```

`ZAM-OpsEvalDefs.h`: C++ code to execute the different flavors of the
operation.  For example,
```
case OP_NEGATE_VC_D:
	frame[z.v1].double_val = -(z.c.double_val);
	break;
```
executes the operation for an operand of type `double` that is a constant
(this instance actually will never be executed at run-time since the
constant will be folded), while
```
case OP_NEGATE_VV_I_field:
	frame[z.v1].record_val->RawFields()->SetField(z.v3).int_val =
	    -(frame[z.v2].int_val);
	break;
```
does so for a variable `int` operand (not a constant), where the target
for where to store the value is a record field rather than a variable, and
```
case OP_NEGATE_VV_I_vec:
	vec_exec(OP_NEGATE_VV_I_vec, frame[z.v1].vector_val,
		frame[z.v2].vector_val);
	break;
```
does the same but for a `vector of int` rather than a single `int` (see
next item).

For all of these, you see that `v1`, `v2`, etc. are members of `z`, a
`ZInst` object representing the instruction currently being executed.

`ZAM-Vec1EvalDefs.h`: C++ code providing the "kernel" for vectorizing the
unary operation:
```
case OP_NEGATE_VC_D_vec:
    vec1[i].double_val = -vec2[i].double_val; break;
case OP_NEGATE_VC_I_vec
    vec1[i].int_val = -vec2[i].int_val; break;
case OP_NEGATE_VV_D_vec
    vec1[i].double_val = -vec2[i].double_val; break;
case OP_NEGATE_VV_I_vec:
    vec1[i].int_val = -vec2[i].int_val; break;
```

`ZAM-OpSideEffects.h`: table initializations for whether the operation has
any side effects (and thus should not be fully optimized away).  For this
example, these 12 elements are all `false`.

<a id="flavors"></a>
`ZAM-Op1FlavorsDefs.h`: table initializations for whether the operation
"writes" to slot `v1` (the common case); only "reads" the value in slot
`v1`; both reads and writes the value; or does not treat `v1` as a frame
slot.  This information is necessary for low-level ZAM optimization.  For
our example, the initialization is `OP1_WRITE` for most instructions, but
`OP1_READ` for those that assign to a record field, since in that case
`v1` specifies the record, which itself is not assigned to.

There are a few more files that can be generated for binary or tertiary
operations, and for when an instruction requires a customized method rather
than those that the templater can generate, but the above captures the
gist of it.

Here is an example of a more involved expression:
```
binary-expr-op Add
op-type I U D S
vector  
eval $1 + $2  
eval_S vector<const BroString*> strings
eval_S strings.push_back($1->AsString())
eval_S strings.push_back($2->AsString())
eval_S auto res = new StringVal(concatenate(strings))
eval_S Unref($$)
eval_S $$ = res
```
It's declared to be a binary operator, tied to the `EXPR_ADD` tag.  This
one includes integer, unsigned, double, and string flavors.  For most of
those, the execution (assigning to the frame slot given by `v1`) is simply
the C++ `+` operator applied to the first and second operands (which come
from frame slots `v2` and `v3`, or `v2` plus the constant `c` field).
However for string types (`S`), the specification supplies more direct C++
code.

Some operations need to treat one of the `v` values as something other
than a frame slot.  For example:
```
expr-op Has-Field
type Ri
eval frame[z.v1].int_val = (frame[z.v2].record_val->RawFields()->HasField(z.v3))
```
specifies how to deal with `EXPR_HAS_FIELD` expressions, but here the first
operand is a record (`R`) and the second is an integer (`i`), representing
the field offset.

<a id="custom-method"></a>
Other operations require their own boutique methods:
```
expr-op In
type VVV
custom-method return CompileInExpr($*);
no-eval
```
Here, the type indicates that the instruction will use `v1`, `v2`, and
`v3`, and that to compile `EXPR_IN` expressions, the templater simply
generates a call to the `ZAM` class's `CompileInExpr()` method.

The templater also knows about relationals, for example here's the
`<` operator:
```
rel-expr-op LT
op-type I U D S T A
vector
eval $1 < $2
eval_S Bstr_cmp($1->AsString(), $2->AsString()) < 0
eval_T $1->IsSubsetOf($2) && $1->Size() < $2->Size()
eval_A $1->AsAddr() < $2->AsAddr()
```
(where `T` specifies table/set types, and `A` addresses).  For relationals,
along with the usual instructions for expressions  the templater also
generates instructions for conditional branches (i.e., `if` statements).
For example, here's the one for `<` with set operands:
```
case OP_LT_VVV_T_cond:
  if ( ! ((frame[z.v1].table_val)->IsSubsetOf((frame[z.v2].table_val)) &&
          (frame[z.v1].table_val)->Size() < (frame[z.v2].table_val)->Size()) ) {
       pc = z.v3; continue;
  }
break;
```
This code checks the sets for a strict subset relationship and if that
does _not_ hold then it loads the PC with a branch target.  If it does
hold, then the instruction completes as usual (via the `break;`, since
this is a `switch` case), which will increment the PC and execute the
following instruction, i.e., the `true` target for the conditional.

<a id="assign-op"></a>
As mentioned above, most of the time instructions compute the result of
evaluating an operation over various operands and then assign the result
to the frame slot specified by `v1`.  Some instructions however do not
require computing an operation and instead directly assign a value.  For
these, some assignments may require memory management (reference counting)
and others do not (and cannot, as there is no object with a reference count
to be manipulated).  The templater automates these distinctions by generating
code for _assignment operations_.  For example:
```
assign-op Field
type R
field-op
eval auto rv = $2.record_val->RawFields()
eval auto v = rv->Lookup(z.v3, ZAM_error)
eval if ( ZAM_error ) ZAM_run_time_error(z.loc, fmt("field value missing: $%s",
                       $2.record_val->Type()->AsRecordType()->FieldName(z.v3)))
eval else @v
```
Here, `@v` indicates that the value to assign is given by the expression
`v`.  The templater set a range of corresponding instructions, one for
each type of value.  For example, here's what it generates for assigning
a subnet value to a record field:
```
case OP_FIELD_VVi_N:
    {
    auto rv = frame[z.v2].record_val->RawFields();
    auto v = rv->Lookup(z.v3, ZAM_error);
    if ( ZAM_error ) ZAM_run_time_error(z.loc, fmt("field value missing: $%s",
                    frame[z.v2].record_val->Type()->AsRecordType()->FieldName(z.v3)));
    else {
        ::Ref(v.subnet_val);
        Unref(frame[z.v1].subnet_val);
        frame[z.v1].subnet_val = v.subnet_val;
    }
    }  
```

Binary operations for which the operands have different types don't get
the full set of scaffolding as provided for other operators, but instead
are specified using internal operations, such as:
```
internal-op Val-Is-In-Table-Cond
op1-read 
type VVV
eval auto op1 = frame[z.v1].ToVal(z.t)
eval if ( ! frame[z.v2].table_val->Lookup(op1.get()) ) { pc = z.v3; continue; }
```
This specification is for the `in` conditional checking whether an index
is in a `set` or `table`, such as `if ( "foo" in my_strings ) ..."`.  The
templater uses this specification to define a ZAM `OP_VAL_IS_IN_TABLE_COND_VVV`
op-code.  It does not provide hooks for automatically translating `EXPR_IN`
nodes to this form.  Instead, the ZAM compiler has explicit code to generate
the instruction as needed
(see the discussion above of [`custom-method`](#custom-method)).
The second line of the specification, `op1-read`,
informs the ZAM compiler that the `v1` frame slot is read to, rather than
assigned to (see the [discussion of `ZAM-Op1FlavorsDefs.h`](#flavors)
above).

Here's an example that puts together several of the notions developed above:
```
internal-assignment-op Call1
type VV
side-effects OP_CALL1_V
side-effects-op-type OP_V
eval std::vector<IntrusivePtr<Val>> args
eval args.push_back(frame[z.v2].ToVal(z.t))
eval f->SetCallLoc(z.loc)
eval auto v_ptr = z.func->Call(args, f)
eval if ( ! v_ptr ) { ZAM_error = true; break; }
eval auto v = v_ptr.get()
eval @v
```
This `OP_CALL1_VV` operation calls a function with one variable argument
and assigns the result to the `v1` slot.  It's both an internal operation
and an [assignment operation](#assign-op).  The instruction is marked as
having _side effects_, and thus even if the return value winds up not being
used (even though it's assigned), the instruction will be kept.  However,
in that case it will be transformed to an `OP_CALL1_V` instruction, which
has an operand type of `OP_V` (meaning that only slot `v1` is used, and
not for an assignment).

The set of instructions also includes operations related to low-level
execution issues, rather than elements of the AST.  For example:
```
op Dirty-Global
op1-internal
type V
eval global_state[z.v1] = GS_DIRTY
```
provides a low-level `OP_DIRTY_GLOBAL_V` instruction that marks a given
global (as specified by a `v1` index into the internal `global_state`
array).  A companion internal operation:
```
op Sync-Globals
type X
eval for ( auto i = 0; i < num_globals; ++i ) {
eval    if ( global_state[i] == GS_DIRTY ) {
eval            auto id = globals[i].id
eval            auto slot = globals[i].slot
eval            auto t = id->Type()
eval            auto v = frame[slot].ToVal(t)
eval            id->SetVal(v)
eval    }
eval    global_state[i] = GS_UNLOADED
eval }
```
loops through `global_state` to synchronize any global that has been
modified to the value associated with the global's identifier, to ensure
consistency with any interpreter execution or event engine access to the
global.  The ZAM compiler uses _Reaching Definitions_ to determine at which
synchronization points (function body return, or a function call) any
globals might have been modified, and thus require executing a synchronization
instruction.

Finally, the ZAM compiler recognizes a number of Zeek Built-in Functions
(BiFs) and [replaces them with ZAM instructions](#Replacing-BiFs).  For
example:
```
internal-op Get-Port-Transport-Proto
type VV
eval auto mask = frame[z.v2].uint_val & PORT_SPACE_MASK
eval auto v = 0; /* TRANSPORT_UNKNOWN */
eval if ( mask == TCP_PORT_MASK ) v = 1
eval else if ( mask == UDP_PORT_MASK ) v = 2
eval else if ( mask == ICMP_PORT_MASK ) v = 3
eval frame[z.v1].uint_val = v
```
replaces the `get_port_transport_proto()` BiF with a version that executes
the equivalent logic, but now without requiring the overhead of a function
call.

Currently there are about 240 templates in `ZAM-Ops.in`.  The templater,
`gen-compiler-templates.sh`, comprises 1,700 lines of (unfortunately
somewhat messy) `awk` code.  Its output for those templates totals about
18,500 lines of C++ code, spread across 20 files.  The bulk of the code
is in `build/src/ZAM-OpsMethodsDefs.h` (5,000) lines and
`build/src/ZAM-OpsEvalDefs.h` (8,000 lines).  The first of these provides
method definitions that generate ZAM instructions for various expressions.
The second reflects the C++ code for executing individual ZAM instructions.

<br>


Replacing BiFs
--------

As mentioned above, the compiler recognizes a number of Zeek built-in
functions and replaces them with custom instructions.  The associated logic
is in `ZBuiltIn.h`/`ZBuiltIn.cc` (although the corresponding instructions
are defined in `ZAM-Ops.in`).

Good candidates for such replacement are BiFs that (1) do not involve
significant processing, so that the gain by avoiding function call overhead
matters, and (2) are executed frequently, such that the
gain by avoiding function call overhead to invoke them outweighs
the maintenance cost of having two separate implementations for the BiF.
A better strategic solution would be to modify `bifcl` to generate versions
of BiFs that can be directly integrated into compiled code.  This however
will require a significant implementation effort.

Currently, the replaced BiFs are:
|Built-In|
|---|
|`Analyzer::__name()`|
|`Broker::__flush_logs()`|
|`Files::__enable_reassembly()`|
|`Files::__set_reassembly_buffer()`|
|`Log::__write()`|
|`current_time()`|
|`get_port_transport_proto()`|
|`network_time()`|
|`reading_live_traffic()`|
|`reading_traces()`|
|`strstr()`|
|`sub_bytes()`|
|`to_lower()`|

<br>

Optimizing ZAM Code
--------

After compiling a function body to `ZInstI` intermediary instructions, the
compiler optimizes the low-level ZAM code.  (The code for doing so resides
in `ZOpt.h`/`ZOpt.cc`.)  This stage has two main steps.

First, the compiler:
1. identifies "dead code" (unreachable instructions)
1. removes unnecessary branches (those that branch to the immediately
following instruct)
1. collapses branches-to-branches
1. identifies assignments to locals for which the value never winds up
being used, removing the instruction if it has no side effects or transforming
it to a version that preserves the side effects without assigning to the
local

This process repeats until none of the stages make any changes to the
program.

Second, the compiler analyzes the lifetime of all of the local variables.
(This includes temporaries that hold the value of global variables so they
can be operated on by ZAM instructions.)  It identifies those that do not
have overlapping scope, and that are also compatible type-wise (holding
types that either require memory management reference counting, or do not).
It "doubles up" such variables such that they share the same ZAM frame
slot.

Due to the optimizer's aggressive inlining, this step can produce massive
savings in doubling up sometimes even dozens of local variables into the
same frame slot.  The smaller frame size not only saves memory produces
significant performance gains because initializing and clearing the frame
upon function entry/exit takes less work.

As with AST optimization, this stage can introduce hard-to-debug errors
if it has any flaws in determining which instructions can be removed or
which variables can be doubled up.  Accordingly, one can use `-O no-ZAM-opt`
to turn off this stage when attempting to localize the source of script
optimization problems.

<br>


Finalizing ZAM Code
--------

To produce an executable function body, the compiler then takes the set
of `ZInstI` intermediary instructions and converts them to an array of
concrete `ZInst` instructions, which then become the heart of a `ZBody`
object (per `ZBody.h`/`ZBody.cc`) that replaces the original function body.

Because `ZInstI` is a subclass of `ZInst`, the intermediary instructions
readily convert to concrete `ZInst` objects.  At this point, the compiler
also finalizes the ZAM frame, and also the size of the `Frame` object
created by the interpreter when the function is invoked.  In the present
design, the interpreter frame only needs to be large enough to accommodate
the function's arguments - no room needs to be allotted for the local
variables.

If the function is non-recursive, then the compiler allocates both the ZAM
frame and the interpreter `Frame` _statically_: they are built once and
do not require tear-down upon function exit because the next time the
function is invoked, the natural process of re-using the frame slots will
recover the previous memory.  (Recursive functions, however, require dynamic
frames for reentrancy.)  This change extends the lifetime of local variables
somewhat, but comes with a significant performance benefit.  It helps here
that the frames are often quite small due to the previous optimization step.


<br>

Saving ZAM Function Bodies
--------

After compiling a function to ZAM code, the optimizer saves it to an
associated `.ZAM` file.  These files are located in the same directory as
the function's source.  The optimizer derives the filename from a combination
of (1) the name of the function body, (2) the line number where it occurs,
and (3) a hash over the AST.  For example, the `.ZAM` file for the
`net_done()` function in the source file `init-bare.zeek` might be named:
```
init-bare.zeek#net_done:1853.648e554a7f2ba77b.ZAM
```
where `1853` reflects the line number and `648e554a7f2ba77b` the hash.

Hashing is meant to ensure that if a source file changes in a semantically
significant way, stale `.ZAM` files for its functions won't get loaded.
If there's any doubt (or if any change has been made to the compiler
itself), it's always prudent (and safe)
to delete all `.ZAM` files and start over.
However, since script optimization can take an appreciably amount of time,
they're in general handy for providing speedier execution in the common
case of scripts not changing, or only a few functions changing.

The file has an ASCII text format for ease of parsing, but it's not meant
to be readable.  The overall format is rigid; the parser expects each
element, if present, to appear in a specific order.  The format does not
include "version" information because the basic notion is that the files
are easy to regenerate and thus it's not important to support older versions.
That could change if `.ZAM` files become a popular way to include scripts
in Zeek packages.

<br>


Executing ZAM Functions
--------

As is the case for any `Stmt` object, executing a `ZBody` proceeds by
invoking its `Exec()` method.  This method in turn invokes `DoExec()`.
The separation between the two allows execution to start at a specific
program counter (PC) location, with the usual start being `pc=0`.  (The
ability to begin execution with a different PC value can potentially support
compiling functions that include `when` statements - not currently relevant.)

Execution begins by marking any globals used in the function body as
"unloaded" (not currently residing in their ZAM frame location) and, for
recursive functions, creating a new ZAM frame and setting all of its
"managed" (reference-counted) slots to `nullptr`.  Currently, the state
of globals is tracked in a dynamic array.  One potential performance
optimization would be to use a static array if the function is not recursive,
similarly to the management of the ZAM frame.

Execution then proceeds by using the `pc` program counter to index the
array of `ZInst` instructions to get the next instruction, and switching
on its op-code in order to execute its C++ implementation.  In the normal
case, after the `switch` case `break`s, `pc` is incremented.  However,
some instructions may instead _branch_ by assigning `pc` to a new location;
or set the `ZAM_error` flag, which will terminate execution.  Execution
also terminates when the `pc` advances (or is set) to a value beyond the
end of the `ZInst` array.

Once execution completes, the dynamic state regarding globals is recovered,
as is the ZAM frame if dynamic due to the function being recursive.

<br>


Representing Zeek Script Values
--------

The Zeek interpreter uses `Val` objects to store values.  At a low level,
these hold one of the following `union` elements:
```
union BroValUnion {
    bro_int_t int_val;
    bro_uint_t uint_val;
    IPAddr* addr_val;
    IPPrefix* subnet_val;
    double double_val;
    BroString* string_val;
    Func* func_val;
    BroFile* file_val;
    RE_Matcher* re_val;
    PDict<TableEntryVal>* table_val;
    std::vector<IntrusivePtr<Val>>* record_val;
    std::vector<IntrusivePtr<Val>>* vector_val;
}
```
This design works well for the interpreter, but for ZAM some of the
representations are at too high of a level, and others at too low of a
level.  First, most of the elements that are pointers to objects point
to lower-level representations of those objects (e.g., `BroString` rather
than `StringVal`) which lack reference-counting and thus complicate
memory management.
Second, the fields of records and the elements of vectors are
pointers to `Val` objects rather than the direct representations of those
objects.

To address these issues, script optimization introduces a new low-level form
(defined in `ZVal.h`/`ZVal.cc`), with these corresponding elements:
```
union ZAMValUnion {
    bro_int_t int_val;
    bro_uint_t uint_val;
    AddrVal* addr_val;
    SubNetVal* subnet_val;
    double double_val;
    StringVal* string_val;
    Func* func_val;
    BroFile* file_val;
    PatternVal* re_val;
    TableVal* table_val;
    RecordVal* record_val;
    VectorVal* vector_val;
    ...
}
```
(It also includes other elements used for ZAM execution.)
This representation overtly addresses the first concern above, as now the
previously lower-level forms are represented using the corresponding `Val`
objects, which provide reference-counting.  The second concern is addressed
by modifying the representation of records and vectors in `BroValUnion`
itself, changing
```
    std::vector<IntrusivePtr<Val>>* record_val;
    std::vector<IntrusivePtr<Val>>* vector_val;
```
to
```
    ZAM_record* record_val;
    ZAM_vector* vector_val;
```
Both `ZAM_record` and `ZAM_vector` (likewise defined in `ZVal.h`/`ZVal.cc`)
use as their underlying representation `std::vector<ZAMValUnion>`.  For
`ZAM_record`, the vector has a fixed size, and the class tracks which
elements are present (and whether those elements require memory management).
For `ZAM_vector`, the vector grows dynamically.  Unlike for the original
interpreter representation, however, these vectors cannot include "holes"
of missing elements.

Due to the need for coordination between ZAM code, the interpreter, and
the event engine, this change to `BroValUnion` is fundamental: it's used
even if script optimization isn't.

The `ZAMValUnion` constructor looks like:
```
ZAMValUnion(IntrusivePtr<Val> v, BroType* t)
```
i.e., given a `Val` object `v` and a type `t`, it constructs the corresponding
ZAM representation.  The constructor explicitly includes the type rather
than taking it from `v` because sometimes the two differ, for example
when `t` is `any` and `v` has a concrete type.  (`ZAMValUnion` represents
`any`-typed values using `Val*`.)

The inverse transformation is provided by the method:
```
IntrusivePtr<Val> ToVal(BroType* t) const
```
Here the type is passed in because `ZAMValUnion`s do _not_ directly track
the type associated with the underlying value.  Not tracking the type
both reduces the memory required and improves performance, because assigning
`ZAMValUnion`s does not require propagating the associated type, which
can also include memory management overhead.  However, it also means that the
compiler must be very careful to itself associate the correct type information
wherever it's needed.

<br>


New Source Files
--------

Here's a summary of new files added to `src/`:
|Source(s)|LOC|Role|
|---|--:|:--|
|Compile.{h,cc}|136|Abstract compiler class, to hide (some) ZAM specifics.|
|DefItem.{h,cc}|239|Used for tracking Reaching Defs.|
|DefPoint.h|92|Used for tracking Reaching Defs.|
|DefSetsMgr.{h,cc}|242|Used for tracking Reaching Defs.|
|GenRDs.{h,cc}|1,419|Generation of Reaching Defs.|
|Inline.{h,cc}|279|Logic for implementing inlining.|
|ProfileFunc.{h,cc}|299|Static analysis of scripting ASTs.|
|ReachingDefs.{h,cc}|442|Main support for tracking Reaching Defs.|
|Reduce.{h,cc}|1,341|Transformation of original AST to reduced form.|
|ScriptAnaly.{h,cc}|590|Driver for script optimization process.|
|StmtBase.h|185|Factored out from Stmt.h, to break some cross-referential #include's.|
|TempVar.{h,cc}|94|Management of temporary variables.|
|UseDefs.{h,cc}|827|Tracking and employing Use-Defs.|
|ZAM-Ops.in|1,983|Templates for ZAM instructions.|
|ZAM.{h,cc}|3,201|Main compiler functions, pre-ZAM-optimization.|
|ZBody.{h,cc}|1,463|Final ZAM function bodies; includes save-to-file functionality.|
|ZBuiltIn.{h,cc}|461|Substitution of ZAM instructions for certain BiFs.|
|ZGen.{h,cc}|197|Helper functions for generating ZAM instructions.|
|ZInst.{h,cc}|1,196|Individual ZAM instructions, along with intermediary form.|
|ZOpt.{h,cc}|1,069|Low-level ZAM optimization.|
|ZVal.{h,cc}|828|Representations of script values.|
|gen-compiler-templates.sh|1,704|Generates C++ files from `ZAM-Ops.in`.|

<br>
The sizes are as of this writing and not meant to be frequently updated.

<br>
<br>

`Expr.{h,cc}` and `Stmt.{h,cc}` also have extensive changes to support
transformation-to-reduced form, exposure of operands, inlining, compiling,
and optimizing.  Numerous other files have more modest changes, such as
to support changes to the internal representations for records and vectors,
parseable `Describe()` representations, parsing of ZAM save files, a more
streamlined approach for initializing record values, and event engine changes
to directly manipulate `ZAM_record` objects.
