# See the file "COPYING" in the main distribution directory for copyright.

# This directory contains templates used to generate virtual functions, opcodes,
# and evaluation code for compiled code.  Each template describes a ZAM
# "operation", which generally corresponds to a set of concrete ZAM
# "instructions".  (See ZInst.h for the layout of ZAM instructions.)  Often
# a single ZAM operation gives rise to a family of instructions that differ
# in either the nature of the instruction's operands (typically, whether
# they are variables residing on the ZAM execution frame, or constants)
# and/or the Zeek type of the operands (e.g., "count" or "double" or "addr").
#
# The Gen-ZAM utility processes this file to generate numerous C++ inclusion
# files that are then compiled into Zeek.  These files span the range of (1)
# hooks that enable run-time generation of ZAM code to execute ASTs (which
# have first been transformed to "reduced" form), (2) specifications of the
# properties of the different instructions, (3) code to evaluate (execute)
# each instruction, and (4) macros (C++ #define's) to aid in writing that
# code.  See Gen-ZAM.h for a list of the different inclusion files.
#
# Operation templates are declarative, other than the imperative C++ snippets
# they include for instruction evaluation/execution.  You specify a template
# using lines of text for which, for the most part, the first word on the
# line designates an "attribute" associated with the template, and the
# remainder of the line provides specifiers/arguments for that attribute.
# A blank line (or end of file) ends the template.  By convention, for
# templates that include C++ evaluation snippets, those are specified as the
# last attribute.  Comments begin with '#' at the start of the line (no
# leading whitespace allowed), and can be intermingled with a template's
# attributes.
#
# Each ZAM instruction includes up to 4 integer values and one constant
# (specified as a ZVal).  Often, the integer values are interpreted as offsets
# ("slots") into the ZAM execution "frame", though sometimes they have other
# meanings, such as the offset of a particular field in a record, or an index
# into the ZAM code for a branch instruction.  Most instructions compute
# some sort of result (expressed as a ZVal) that is stored into the frame
# slot specified by the instruction's first integer value.  We refer to this
# target as the "assignment slot", and to the other 3 integer values as
# "operands".  Thus, for example, an instruction with two operands used the
# first 3 integer values, the first as the assignment slot and the other two
# for computing the result to put in that slot.
#
# Instruction templates have one or more "type"s associated with them (as
# discussed below) specifying the types of operands (variables corresponding
# to slots, or constants) associated with the instruction.  In the evaluation
# code for an instruction, these are referred to with $-parameters, such as
# $1 for the first operand. The special parameter $$ refers to the *assignment
# target* of the instruction, if applicable. These parameters always come
# first when specifying an instruction's type. For example, a type of "VVC"
# specifies an instruction with two variables and one constant associated
# with it. If the instruction assigns a value, then in the evaluation these
# will be specified as $$, $1 and $2, respectively. If it does not (usually
# reflected by the template having the "op1-read" attribute) then they
# are specified as $1, $2 and $3, respectively. See "eval" below.
#
# The first attribute of each template states the type of operation specified
# in the template, along with the name of the operation.  The possible types
# are:
#
# 	op	an operation that generally corresponds to a single ZAM
# 		instruction, and is fully specified
#
# 	expr-op	an operation corresponding to an AST expression node
# 		(some sort of Expr object).  Gen-ZAM generates code for
# 		automatically converting Expr objects to ZAM instructions.
#		The name of the operation must match that used in the AST
#		tag, so for example for "expr-op Foo" there must be a
#		corresponding "EXPR_FOO" tag.
#
# 	unary-expr-op	an expr-op for a unary Expr object
# 	binary-expr-op	an expr-op for a binary Expr object
# 	rel-expr-op	an expr-op for a (binary) Expr object that
# 			represents a relational operation
#
# 	assign-op       directly assigning either a ZVal or a record field
# 			to either a frame slot or a record field
#
# 	unary-op        an operation with one operand that requires special
# 			treatment that doesn't fit with how unary-expr-op's
# 			are expressed
#
# 	direct-unary-op an operation with one operand that corresponds to
# 			a specific ZAMCompiler method for generating its
# 			instruction
#
# 	internal-op	similar to "op", but for ZAM instructions only used
# 			internally, and thus not having any AST counterpart
# 	internal-assignment-op	the same, for operations that assign ZVals
# 				produced by loading interpreter variables
# 				or calling functions
#
# After specifying the type of operation, you list additional attributes to
# fill out the template, ending by convention with the C++ evaluation snippet
# (if appropriate).  The most significant (and complex) of these are:
#
# 	class	specifies how to interpret the operation in terms of ZAM
# 		instruction slots (and constant).  The specification is
# 		in terms of single-letter mnemonics for the different
# 		possible classes:
#
# 			F special value designating a record field being
# 			  assigned to
# 			H event handler
# 			L list of values
# 			O opaque value (here, "opaque" refers to ZAM
# 			  internals, not OpaqueVal)
# 			R record
# 			V variable (frame slot)
# 			X used to indicate an empty specifier
# 			b branch target
# 			f iteration information associated with table "for" loop
# 			g access to a global
# 			i integer constant, often a record field offset
#			s iteration information associated with stepping
#			  through a vector or string
#
# 		The full specification consists of concatenating mnemonics
# 		with the order left-to-right corresponding to each of the
# 		instruction's 4 integer values (stopping with the last one
# 		used).  If the operation includes a constant, then it is
# 		listed at the point reflecting where the constant is used as
# 		an operand.  For example, a class of "VVCV" means that the
# 		first integer is used as a frame variable (i.e., the usual
# 		"assignment slot"), the second integer (first "operand") is
# 		also a frame variable, the second operand is the instruction's
# 		constant, and the third operand is the instruction's third
# 		integer value, with the fourth integer value not being used.
#
#	classes	specifies a number of "class" values to instantiate over.
#		Cannot be combined with "class", nor used for expressions.
#
# 	op-type for some form of expr-op, specifies to which Zeek scripting
# 		types the expression applies:
#
# 			A addr
# 			D double
# 			F file
# 			I int
# 			N subnet
# 			P pattern
# 			R record
# 			S string
# 			T table
# 			U count
# 			V vector
#
# 		along with two special types: 'X' indicates that Gen-ZAM
# 		should not iterate over any possible values, and '*'
# 		indicates that Gen-ZAM should additionally iterate over
# 		all of possible values not explicitly listed (used in
# 		conjunction with eval-type - see below)
#
#	op-types	similar to op-type, but lists a type for each operand
#			(including assignment target), so for example "A N A"
#			would correspond to a 3-operand instruction for which
#			the first operand (or assignment target) is an "addr",
#			the second a "subnet", and the third another "addr".
#
#		Note that these types collectively apply to each instance of
#		an operation, whereas listing multiple "op-type" types
#		iterates through those one-at-a-time in turn (and generally
#		the point is that the each type applies to *all* operands,
#		rather than a per-operand list). Given that, the two are
#		incompatible.
#
#		For operands corresponding to 'i' or any of the internal types,
#		such as 'b', 'f', 'g', and 's', the corresponding type to
#		list is 'I', used for integer access.
#
#	inverse	For instructions that can be used in conditionals, specifies
#		the "inverse" conditional. For example, the inverse for LE
#		(less-than-or-equal) is GT (greater-than). This attribute
#		isn't needed for instructions that have a "*-Not-*Cond"
#		form (like "Val2-Is-Not-In-Table-Cond"), since for them
#		Gen-ZAM can automatically infer that the inverse from
#		the structure of the name (e.g., "Val2-Is-In-Table-Cond").
#
# 	eval	specifies a block of C++ code used to evaluation the
# 		execution of the instruction.  The block begins with the
# 		remainder of the "eval" line and continues until either a
# 		blank line or a line that starts with non-whitespace.
#
# 		Blocks can include special '$' parameters that Gen-ZAM
# 		automatically expands.  "$1" refers to an operation's first
# 		operand, "$2" to its second, etc.  "$$" refers to the
# 		operation's assignment target.
#
# 		For simple expr-op's you can express the block as simply
# 		the C++ expression to compute.  For example, for multiplication
# 		(named "Times"), the "eval" block is simply "$1 * $2",
# 		rather than "$$ = $1 * $2"; Gen-ZAM knows to expand it
# 		accordingly.
#
# 		Finally, to help with avoiding duplicate code, you can
# 		define macros that expand to code snippets you want to use
# 		in multiple places.  You specify these using a "macro"
# 		keyword followed by the name of the macro and an evaluation
# 		block.  Macros behave identically to C++ #define's, except
# 		you don't use "\" to continue them across line breaks, but
# 		instead just indent the lines you want included, ending
# 		(as with "eval" blocks) with an empty line or a line that
# 		starts with non-whitespace.
#
# We list the remaining types of attributes alphabetically.  Note that some
# only apply to certain types of operations.
#
# 	assign-val	for an assignment operation, the name of the
# 			C++ variable that holds the value to assign
#
# 	custom-method	a ZAMCompiler method that Gen-ZAM should use for
# 			this operation, rather than generating one
#
# 	eval-mixed	an expression "eval" block that applies to two
# 			different op-type's
#
# 	eval-type	evaluation code associated with one specific op-type
#
# 	explicit-result-type	the operation's evaluation yields a ZVal
# 				rather than a low-level C++ type
#
# 	field-op	the operation is a direct assignment to a record field
#
# 	includes-field-op	the operation should include a version
# 				that assigns to a record field as well as a
# 				version for assigning to a frame variable
#
# 	indirect-call	the operation represents an indirect call (through
# 			a global variable, rather than directly).  Only
#			meaningful if num-call-args is also specified.
#
# 	indirect-local-call	same, but via a local variable rather than
#			global
#
# 	method-post	C++ code to add to the end of the method that
# 			dynamically generates ZAM code
#
# 	no-const	do not generate a version of the unary-expr-op
# 			where the operand is a constant
#
# 	no-eval		this operation does not have an "eval" block
# 			(because it will be translated instead into internal
# 			operations)
#
# 	num-call-args	indicates that the operation is a function call,
# 			and specifies how many arguments the call takes.
# 			A specification of 'n' means "build a ZAM instruction
# 			for calling with an arbitrary number of arguments".
#
# 	op1-internal    states that the operation's treatment of the
# 			instruction's first integer value is for internal
# 			purposes; the value does not correspond to a frame
# 			variable
#
# 	op1-read	the operation treats the instruction's first integer
# 			value as a frame variable, but only reads the value.
# 			(The default is that the frame variable is written
# 			to but not read.)
#
# 	op1-read-write	the operation treats the instruction's first integer
# 			value as a frame variable, and both reads and
# 			writes the value.
#
# 	precheck	a test conducted before evaluating an expression,
#			which is skipped if the test is true. Must be used
#			in conjunction with precheck-action.
#
# 	precheck-action	code to execute if a precheck is true, instead
#			of evaluating the expression. Must be used in
#			conjunction with precheck.
#
# 	set-type	the instruction's primary type comes from either the
# 			assignment target ("$$"), the first operand ("$1"),
# 			or the second operand ("$2")
#
# 	set-type2       the same as set-type but for the instruction's
# 			secondary type
#
# 	side-effects	the operation has side-effects, so even if its
# 			assignment target winds up being "dead" (the value is
# 			no longer used), the operation should still occur.
# 			Optionally, this attribute can include two arguments
# 			specifying the ZAM opcode to use if the assignment
# 			is dead, and the internal "type" of that opcode.
#
# 			For example, "side-effects OP_CALL1_V OP_V" means
# 			"this operation has side-effects; if eliminating
# 			its assignment, change the ZAM op-code to OP_CALL1_V,
# 			which has an internal type of OP_V".
#
# 	vector          generate a version of the operation that takes
# 			vectors as operands
#
# Finally, a note concernning comments: due to internal use of C++ #define
# macros, comments in C++ code should use /* ... */ rather than // delimiters.
