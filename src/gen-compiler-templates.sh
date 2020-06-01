#! /bin/sh

awk '
BEGIN	{
	base_class_f = "CompilerBaseDefs.h"
	exprsC1_f = "CompilerOpsExprsDefsC1.h"
	exprsC2_f = "CompilerOpsExprsDefsC2.h"
	exprsC3_f = "CompilerOpsExprsDefsC3.h"
	exprsV_f = "CompilerOpsExprsDefsV.h"

	conds_f = "ZAM-Conds.h"
	sub_class_f = "ZAM-SubDefs.h"
	ops_f = "ZAM-OpsDefs.h"
	ops_names_f = "ZAM-OpsNamesDefs.h"
	op1_flavors_f = "ZAM-Op1FlavorsDefs.h"
	ops_direct_f = "CompilerOpsDirectDefs.h"
	ops_eval_f = "ZAM-OpsEvalDefs.h"
	vec1_eval_f = "ZAM-Vec1EvalDefs.h"
	vec2_eval_f = "ZAM-Vec2EvalDefs.h"
	methods_f = "ZAM-OpsMethodsDefs.h"

	prep(exprsC1_f)
	prep(exprsC2_f)
	prep(exprsC3_f)
	prep(exprsV_f)

	args["X"] = "()"
	args["O"] = "(OpaqueVals* v)"
	args["Ri"] = "(const NameExpr* n1, const NameExpr* n2, int field)"
	args["V"] = "(const NameExpr* n)"
	args["Vi"] = "(const NameExpr* n, int i)"
	args["CVi"] = "(const ConstExpr* c, const NameExpr* n, int i)"
	args["VV"] = "(const NameExpr* n1, const NameExpr* n2)"
	args["VO"] = "(const NameExpr* n, OpaqueVals* v)"
	args["HL"] = "(EventHandler* h, const ListExpr* l)"
	args["VVV"] = "(const NameExpr* n1, const NameExpr* n2, const NameExpr* n3)"
	args["VVVV"] = "(const NameExpr* n1, const NameExpr* n2, const NameExpr* n3, const NameExpr* n4)"
	args["C"] = "(const ConstExpr* c)"
	args["VC"] = "(const NameExpr* n, const ConstExpr* c)"
	args["VVC"] = "(const NameExpr* n1, const NameExpr* n2, const ConstExpr* c)"
	args["VVVC"] = "(const NameExpr* n1, const NameExpr* n2, const NameExpr* n3, const ConstExpr* c)"
	args["VVCV"] = "(const NameExpr* n1, const NameExpr* n2, const ConstExpr*c, const NameExpr* n3)"
	args["VVi"] = "(const NameExpr* n1, const NameExpr* n2, int i)"
	args["VCi"] = "(const NameExpr* n, const ConstExpr* c, int i)"
	args["VCV"] = "(const NameExpr* n1, const ConstExpr* c, const NameExpr* n2)"

	args["VLV"] = "(const NameExpr* n1, const ListExpr* l, const NameExpr* n2)"
	args["VLC"] = "(const NameExpr* n, const ListExpr* l, const ConstExpr* c)"
	args["VVL"] = "(const NameExpr* n1, const NameExpr* n2, const ListExpr* l)"
	args["ViHL"] = "(const NameExpr* n, int i, EventHandler* h, const ListExpr* l)"
	args["CiHL"] = "(const ConstExpr* c, int i, EventHandler* h, const ListExpr* l)"

	args2["X"] = ""
	args2["O"] = "reg"
	args2["Ri"] = "n1, n2, field"
	args2["V"] = "n"
	args2["Vi"] = "n, i"
	args2["CVi"] = "c, n, i"
	args2["VV"] = "n1, n2"
	args2["VO"] = "n, reg"
	args2["VVV"] = "n1, n2, n3"
	args2["VLV"] = "n1, l, n2"
	args2["VLC"] = "n, l, c"
	args2["VVVV"] = "n1, n2, n3, n4"
	args2["C"] = "c"
	args2["VC"] = "n, c"
	args2["VVC"] = "n1, n2, c"
	args2["VVVC"] = "n1, n2, n3, c"
	args2["VVCV"] = "n1, n2, c, n3"
	args2["VVi"] = "n1, n2, i"
	args2["VCi"] = "n, c, i"
	args2["VCV"] = "n1, c, n2"

	exprC1["VC"] = "lhs, r1->AsConstExpr()";
	exprC1["VCV"] = "lhs, r1->AsConstExpr(), r2->AsNameExpr()"

	exprC2["VVC"] = "lhs, r1->AsNameExpr(), r2->AsConstExpr()"
	exprC2["VVCV"] = "lhs, r1->AsNameExpr(), r2->AsConstExpr(), r3->AsNameExpr()"
	exprC2["VVi"] = "lhs, r1->AsNameExpr(), r2->AsConstExpr()->Value()->AsInt()"

	exprC3["VVVC"] = "lhs, r1->AsNameExpr(), r2->AsNameExpr(), r3->AsConstExpr()"

	exprV["X"] = ""
	exprV["V"] = "lhs"
	exprV["VV"] = "lhs, r1->AsNameExpr()"
	exprV["VVV"] = "lhs, r1->AsNameExpr(), r2->AsNameExpr()"
	exprV["VLV"] = "lhs, r1->AsListExpr(), r2->AsNameExpr()"
	exprV["VLC"] = "lhs, r1->AsListExpr(), r2->AsConstExpr()"
	exprV["VVVV"] = "lhs, r1->AsNameExpr(), r2->AsNameExpr(), r3->AsNameExpr()"

	accessors["i"] = accessors["I"] = ".int_val"
	accessors["u"] = accessors["U"] = ".uint_val"
	accessors["d"] = accessors["D"] = ".double_val"

	accessors["A"] = ".addr_val"
	accessors["N"] = ".subnet_val"
	accessors["P"] = ".re_val"
	accessors["R"] = ".record_val"
	accessors["S"] = ".string_val"
	accessors["T"] = ".table_val"
	accessors["V"] = ".vector_val"
	accessors["X"] = "###"

	++is_managed["A"]
	++is_managed["N"]
	++is_managed["R"]
	++is_managed["S"]
	++is_managed["V"]	# other than vector-of-any, sigh

	# We break these out because here the type structure does not match
	# the argument structure.  Instead, these are special types known
	# to the part of the templator that deals with assignment operations.

	# Types associated with the dispatch side of assignment operators.
	++assign_types["RV"]
	++assign_types["RC"]
	++assign_types["FV"]
	++assign_types["FC"]
	++assign_types["XV"]
	++assign_types["XC"]

	# Assignments to values computed from record fields "x=y$f".
	args["RV"] = \
		"(const NameExpr* n1, const NameExpr* n2, const FieldExpr* f)"
	args["RC"] = \
		"(const NameExpr* n, const ConstExpr* c, const FieldExpr* f)"

	# Assignments to record fields "x$f = y".
	args["FV"] = "(const NameExpr* n1, int field, const NameExpr* n2)"
	args["FC"] = "(const NameExpr* n, int field, const ConstExpr* c)"

	# Vanilla assignments "x=y".
	args["XV"] = "(const NameExpr* n1, const NameExpr* n2)"
	args["XC"] = "(const NameExpr* n, const ConstExpr* c)"

	args2["RV"] = "n1, n2, field"
	args2["RC"] = "n, c, field"
	args2["FV"] = "n1, n2, field"
	args2["FC"] = "n, c, field"
	args2["XV"] = "n1, n2"
	args2["XC"] = "n, c"

	method_extra_prefix["R"] = "auto field = f->Field();"

	# For an assign-to-any, then we will need the instruction
	# type field set to the type of the RHS.  It does no harm
	# to just always do that.
	method_extra_suffix["R"] = "z.t = $2->Type()->AsRecordType()->FieldType(field);"
	method_extra_suffix["X"] = "z.t = t;"

	# Whether for generated statements to take their type from the
	# main assignment target (1) or from the first operand (0).
	use_target_for_type["F"] = 0
	use_target_for_type["R"] = 1
	use_target_for_type["X"] = 0

	# Accessor for the type, if something special required.
	specific_type["F"] = ".get()"
	specific_type["R"] = ".get()"
	specific_type["X"] = ".get()"

	# Evaluation of @ parameters in assignments has two basic types,
	# "short" (0) and "long" (1).  Short means to construct a new local
	# "v" with the @ target.  Long means that an existing value is
	# being replaced, so it should be deleted if managed and then
	# the assignment is done directly into the frame.

	SHORT = 0
	LONG = 1

	assignment_type["F"] = SHORT
	assignment_type["R"] = LONG
	assignment_type["X"] = LONG

	# Templates for mapping "bare" frame assignments to specific
	# transformations/memory management, depending on the type
	# of the assignment.  Indexed by both the type and 0/1 for
	# short/long.

	assign_tmpl["A", SHORT] = "auto av = new IPAddr(*($1.addr_val));\nZAMValUnion $$;\n$$.addr_val = av;"
	assign_tmpl["N", SHORT] = "auto nv = new IPPrefix(*($1.subnet_val));\nZAMValUnion $$;\n$$.subnet_val = nv;"
	assign_tmpl["R", SHORT] = "auto rv = $1.record_val->ShallowCopy();\nZAMValUnion $$;\n$$.record_val = rv;"
	assign_tmpl["S", SHORT] = "auto sv = new BroString(*($1.string_val));\nZAMValUnion $$;\n$$.string_val = sv;"
	assign_tmpl["V", SHORT] = "auto vv = $1.vector_val->ShallowCopy();\nZAMValUnion $$;\n$$.vector_val = vv;"
	assign_tmpl["ANY", SHORT] = "ZAMValUnion $$ = $1;"
	assign_tmpl["", SHORT] = "ZAMValUnion $$ = $1;"

	assign_tmpl["A", LONG] = "auto av = new IPAddr(*($1.addr_val));\ndelete $$.addr_val;\n$$.addr_val = av;"
	assign_tmpl["N", LONG] = "auto nv = new IPPrefix(*($1.subnet_val));\ndelete $$.subnet_val;\n$$.subnet_val = nv;"
	assign_tmpl["R", LONG] = "auto rv = $1.record_val->ShallowCopy();\ndelete $$.record_val;\n$$.record_val = rv;"
	assign_tmpl["S", LONG] = "auto sv = new BroString(*($1.string_val));\ndelete $$.string_val;\n$$.string_val = sv;"
	assign_tmpl["V", LONG] = "auto vv = $1.vector_val->ShallowCopy();\ndelete $$.vector_val;\n$$.vector_val = vv;"
	assign_tmpl["ANY", LONG] = "$$.any_val = TrackValPtr($1.ToVal(z.t));"
	assign_tmpl["", LONG] = "$$ = $1;"


	# Update eval(...) below

	eval_selector["I"] = ""
	eval_selector["i"] = "i"
	eval_selector["U"] = ""
	eval_selector["u"] = "u"
	eval_selector["D"] = ""
	eval_selector["d"] = "d"
	eval_selector["A"] = "A"
	eval_selector["N"] = "N"
	eval_selector["P"] = "P"
	eval_selector["R"] = "R"
	eval_selector["S"] = "S"
	eval_selector["T"] = "T"
	eval_selector["V"] = "V"

	++no_vec["P"]
	++no_vec["R"]
	++no_vec["T"]
	++no_vec["V"]
	++no_vec["A", "I"]

	method_map["i"] = method_map["I"] = "i_t == TYPE_INTERNAL_INT"
	method_map["u"] = method_map["U"] = "i_t == TYPE_INTERNAL_UNSIGNED"
	method_map["d"] = method_map["D"] = "i_t == TYPE_INTERNAL_DOUBLE"
	method_map["A"] = "i_t == TYPE_INTERNAL_ADDR"
	method_map["N"] = "i_t == TYPE_INTERNAL_SUBNET"
	method_map["P"] = "tag == TYPE_PATTERN"
	method_map["R"] = "tag == TYPE_RECORD"
	method_map["S"] = "i_t == TYPE_INTERNAL_STRING"
	method_map["T"] = "tag == TYPE_TABLE"

	# We need to explicitly check for any/not-any because we go through
	# the op-types via dictionary traversal (i.e., unpredcitable order).
	method_map["V"] = "tag == TYPE_VECTOR"

	# Maps original op-types (for example, for relationals) to the
	# equivalent when using them in a conditional.
	cond_type["VVV"] = "VVi"
	cond_type["VVC"] = "VCi"
	cond_type["VCV"] = "CVi"

	mixed_type_supported["P", "S"]
	mixed_type_supported["A", "I"]

	# Suffix used for vector operations.
	vec = "_vec"

	# Suffix used for conditionals.
	cond = "_cond"
	}

$1 == "op"	{ dump_op(); op = $2; next }
$1 == "expr-op"	{ dump_op(); op = $2; expr_op = 1; next }
$1 == "assign-op" { dump_op(); op = $2; assign_op = 1; next }
$1 == "unary-op"	{ dump_op(); op = $2; ary_op = 1; next }
$1 == "direct-unary-op" {
	dump_op(); op = $2; direct_method = $3; direct_op = 1; next
	}
$1 == "unary-expr-op"	{ dump_op(); op = $2; expr_op = 1; ary_op = 1; next }
$1 == "binary-expr-op"	{ dump_op(); op = $2; expr_op = 1; ary_op = 2; next }
$1 == "rel-expr-op"	{
	dump_op();
	op = $2; expr_op = 1; ary_op = 2; rel_op = 1; cond_op = 1;
	next
	}
$1 == "internal-op"	{ dump_op(); op = $2; internal_op = 1; next }
$1 == "internal-binary-op" {
	dump_op(); op = $2; binary_op = internal_op = 1; next
	}

$1 == "op1-read"	{ op1_flavor = "OP1_READ"; next }
$1 == "op1-write"	{ op1_flavor = "OP1_WRITE"; next }
$1 == "op1-read-write"	{ op1_flavor = "OP1_READ_WRITE"; next }
$1 == "op1-internal"	{ op1_flavor = "OP1_INTERNAL"; next }

$1 == "op-accessor"	{ op1_accessor = op2_accessor = $2; next }
$1 == "op1-accessor"	{ op1_accessor = $2; next }
$1 == "op2-accessor"	{ op2_accessor = $2; next }

$1 == "no-const"	{ no_const = 1; next }
$1 == "type"	{ type = $2; next }
$1 == "type-selector"	{ type_selector = $2; next }
$1 == "vector"	{ vector = 1; next }
$1 ~ /^op-type(s?)$/	{ build_op_types(); next }
$1 == "opaque"	{ opaque = 1; next }

$1 == "set-type"	{ set_type = $2; next }
$1 == "set-expr"	{ set_expr = $2; next }

$1 ~ /^eval((_([iudANPRSTV]))?)$/	{
		if ( $1 != "eval" )
			{
			# Extract subtype specifier.
			eval_sub = $1
			sub(/eval_/, "", eval_sub)

			if ( ! (eval_sub in eval_selector) ||
			     eval_selector[eval_sub] == "" )
				gripe("bad eval subtype specifier")
			}
		else
			eval_sub = ""

		new_eval = all_but_first()
		if ( (! operand_type || eval_sub || binary_op) && ! cond_op )
			# Add semicolons for potentially multi-line evals.
			new_eval = new_eval ";"

		if ( eval[eval_sub] )
			{
			if ( operand_type && ! eval_sub && ! binary_op &&
			     op_type_rep != "X" )
				gripe("cannot intermingle op-type and multi-line evals")

			eval[eval_sub] = eval[eval_sub] "\n\t\t" new_eval

			# The following variables are just to enable
			# us to produce tidy-looking switch blocks.
			multi_eval = "\n\t\t"
			eval_blank = ""
			}
		else
			{
			eval[eval_sub] = new_eval
			eval_blank = " "
			}
		next
		}

$1 == "eval-mixed"	{
		ev_mix1 = $2
		ev_mix2 = $3
		mix = all_but_first_n(3)
		if ( mix_eval )
			mix_eval = mix_eval ";\n\t" mix
		else
			mix_eval = mix
		next
		}

$1 == "no-eval"	{ no_eval = 1; next }

$1 == "custom-method"	{ custom_method = all_but_first(); next }
$1 == "method-pre"	{ method_pre = all_but_first(); next }
$1 == "eval-pre"	{ eval_pre = all_but_first() ";"; next }

/^#/		{ next }
/^[ \t]*$/	{ next }

	{ gripe("unrecognized compiler template line: " $0) }

END	{
	dump_op()

	finish(exprsC1_f, "C1")
	finish(exprsC2_f, "C2")
	finish(exprsC3_f, "C3")
	finish(exprsV_f, "V")

	finish_default_ok(ops_direct_f)
	}

function build_op_types()
	{
	operand_type = 1

	for ( i = 2; i <= NF; ++i )
		{
		if ( $i in accessors || $i == "*" )
			++op_types[$i]
		else
			gripe("bad op-type " $i)
		}

	# The "rep" is simply one of the listed types, which we use
	# to generate the corresponding base method only once.
	op_type_rep = $2
	}

function all_but_first()
	{
	return all_but_first_n(1)
	}

function all_but_first_n(n)
	{
	all = ""
	for ( i = n+1; i <= NF; ++i )
		{
		if ( i > n+1 )
			all = all " "

		all = all $i
		}

	return all
	}

function dump_op()
	{
	if ( ! op )
		return

	if ( binary_op )
		{
		build_internal_binary_op()
		clear_vars()
		return
		}

	if ( direct_op )
		{
		build_direct_op(direct_method)
		clear_vars()
		return
		}

	if ( assign_op )
		{
		build_assignment_op(op, type)
		clear_vars()
		return
		}

	if ( ! ary_op )
		{
		ex = eval[""]
		build_op(op, type, "", "", ex, ex, 0, 0)
		clear_vars()
		return
		}

	if ( ! operand_type )
		# This op does not have "flavors".  Give it one
		# empty flavor to use in iterating.
		++op_types[""]

	# Note, for most operators the constant version would have
	# already been folded, but for some like AppendTo, they
	# cannot, so we account for that possibility here.

	# Loop over constant, var for first operand
	for ( j = 0; j <= 1; ++j )
		{
		if ( no_const && j == 0 )
			continue;

		op1 = j ? "V" : "C"

		if ( ary_op == 1 )
			{
			# Loop over operand types for unary operator.
			for ( i in op_types )
				{
				if ( i == "X" )
					{
					# Just use the raw eval.
					ex = eval[""]
					esel = ""
					}
				else
					{
					sel = eval_selector[i]
					esel = eval[sel]
					ex = expand_eval(esel,
							eval_pre, expr_op,
							i, i, j, 0)
					}

				build_op(op, "V" op1, i, i, esel, ex, j, 0)
				}

			continue;
			}

		# Loop over constant, var for second operand.  We do not
		# currently worry about "no_const" here.
		for ( k = 0; k <= 1; ++k )
			build_op_combo(op1, j, k)
		}

	clear_vars()
	}

function build_op_combo(op1, j, k)
	{
	if ( ! j && ! k )
		# Do not generate CC, should have been folded.
		return

	op2 = k ? "V" : "C"

	for ( i in op_types )
		{
		sel = eval_selector[i]
		ex = expand_eval(eval[sel], eval_pre, expr_op, i, i, j, k)
		build_op(op, "V" op1 op2, i, i, eval[sel], ex, j, k)
		}

	if ( mix_eval )
		{
		ex = expand_eval(mix_eval, eval_pre, expr_op, ev_mix1, ev_mix2, j, k)
		build_op(op, "V" op1 op2, ev_mix1, ev_mix2, mix_eval, ex, j, k)
		}
	}

function build_internal_binary_op()
	{
	# Internal binary op.  Do not generate method stuff for it,
	# but do generate eval stuff.
	for ( j = 0; j <= 1; ++j )
		{
		op1 = j ? "V" : "C"

		# Loop over constant, var for second operand
		for ( k = 0; k <= 1; ++k )
			{
			if ( ! j && ! k )
				# Do not generate CC, should have
				# been folded.
				continue;

			op2 = k ? "V" : "C"

			# See comment below for the role of op3.
			op3 = (j && k) ? "v3" : "v2"

			a1 = ("auto op1 = " \
			      (j ? "frame[z.v2]" : "z.c") \
			      "." op1_accessor ";\n\t\t")

			a2 = ("auto op2 = " \
			      (k ? "frame[z." op3 "]": "z.c") \
			      "." op2_accessor ";\n\t\t")

			assign = "frame[z.v1]" accessors[op_type_rep]

			eval_copy = a1 a2 eval[""]
			gsub(/\$\$/, assign, eval_copy)

			build_op(op, "V" op1 op2, "", "",
					eval_copy, eval_copy, j, k)
			}
		}
	}

function build_direct_op(method)
	{
	orig_op = op
	gsub(/-/, "_", op)
	upper_op = toupper(op)

	print ("\tcase EXPR_" upper_op \
		":\treturn c->" method "(lhs, rhs);") >ops_direct_f
	}

function build_assignment_op(op, type)
	{
	build_assignment_dispatch(op, type)

	# Now generate the specific flavors.
	for ( flavor in is_managed )
		build_assignment(op, type, flavor, eval[""])

	# Handle assignment-to-any.
	build_assignment(op, type, "ANY", eval[""])

	# Default assignment where no special work is needed.
	build_assignment(op, type, "", eval[""])
	}

function build_assignment_dispatch(op, type)
	{
	build_assignment_dispatch2(op, type, 0)
	build_assignment_dispatch2(op, type, 1)
	}

function build_assignment_dispatch2(op, type, is_var)
	{
	# Generate generic versions of the assignment, which provide custom
	# methods for dispatching to the specific flavors.
	no_eval = 1

	targ = is_var ? "n1" : "n"
	rhs_op = is_var ? "n2" : "c"
	type_base = use_target_for_type[type] ? targ : rhs_op

	atype = type (is_var ? "V" : "C")

	custom_method = \
		"auto t = " type_base "->Type()" specific_type[type] ";\n" \
		"\tauto tag = t->Tag();\n" \
		"\tauto i_t = t->InternalType();\n" \
		"\tZInst z;"

	if ( type in method_extra_prefix )
		custom_method = custom_method "\n\t" method_extra_prefix[type]

	# Do the "ANY" case first, since it is dispatched on the
	# type of n1 rather than n2.
	custom_method = custom_method "\n\t" \
		build_assign_case(op, atype, "ANY", targ "->Type()->Tag() == TYPE_ANY")

	for ( flavor in is_managed )
		custom_method = custom_method \
			build_assign_case(op, atype, flavor, method_map[flavor], is_var)

	# Add the default case.
	custom_method = custom_method "\n" build_assign_case(op, atype, "", "", is_var)

	if ( type in method_extra_suffix )
		{
		xtra = method_extra_suffix[type]
		gsub(/\$2/, rhs_op, xtra)
		custom_method = custom_method "\n\t" xtra
		}

	custom_method = custom_method "\n" \
		"\treturn AddInst(z);"

	build_op(op, atype, "", "", "", "", is_var, "")

	no_eval = 0
	custom_method = ""
	}

function build_assignment(op, type, flavor, ev)
	{
	build_assignment2(op, type, flavor, 0, ev)
	build_assignment2(op, type, flavor, 1, ev)
	}

function build_assignment2(op, type, flavor, is_var, ev)
	{
	if ( index(ev, "@") == 0 )
		gripe("no @ specifier in assignment op")

	assign_val = ev
	sub(/.*@/, "", assign_val)
	sub(/[ \t;].*/, "", assign_val)

	a_t = assignment_type[type]

	tmpl = assign_tmpl[flavor, a_t]

	if ( a_t == LONG )
		# Allow for long form to be for example in an if-else
		# clause.  We do not do this for SHORT however because
		# for it the whole point is that the $$ variable is
		# subsequently accessible.
		tmpl = "{\n" tmpl "\n}"

	gsub(/\$1/, assign_val, tmpl)
	gsub(/\$\$/, a_t ? "frame[z.v1]" : "v", tmpl)

	gsub(/@[a-zA-Z$0-9]*/, tmpl, ev)
	gsub(/\$2/, is_var ? "frame[z.v2]" : "z.c", ev)

	build_op(op, "V" (is_var ? "V" : "C") "i", flavor, "", ev, ev, is_var, 0)
	}

function build_assign_case(op, atype, flavor, cond, is_var)
	{
	targ = is_var ? "n1" : "n"
	operand = is_var ? "n2" : "c"

	full_op = "OP_" toupper(op) "_V" (is_var ? "V" : "C") "i"
	gsub(/-/, "_", full_op)

	assign_args = args2[atype]

	if ( ! flavor )
		return "\t\tz = GenInst(this, " full_op ", " assign_args ");"

	full_op = full_op "_" flavor

	return "if ( " cond " )\n" \
		"\t\tz = GenInst(this, " full_op ", " assign_args ");\n" \
		"\telse "
	}

function expand_eval(e, pre_eval, is_expr_op, otype1, otype2, is_var1, is_var2)
	{
	laccessor = raccessor1 = raccessor2 = ""
	expr_app = ""
	if ( otype1 && otype1 != "*" )
		{
		if ( ! (otype1 in accessors) )
			gripe("bad operand_type: " otype1)
		if ( ! (otype2 in accessors) )
			gripe("bad operand_type: " otype2)

		raccessor1 = accessors[otype1]
		raccessor2 = accessors[otype2]

		if ( rel_op )
			laccessor = accessors["I"]
		else
			laccessor = raccessor1

		expr_app = ";"
		}

	e_copy = e
	pre_copy = pre_eval
	rep1 = "(" (is_var1 ? "frame[z.v2]" : "z.c") raccessor1 ")"
	gsub(/\$1/, rep1, e_copy)
	gsub(/\$1/, rep1, pre_copy)

	if ( ary_op == 2 )
		{
		# If one of the operands is a constant, then we use
		# v2 and not v3 to hold the other (non-constant) operand.
		op3 = (is_var1 && is_var2) ? "v3" : "v2"
		rep2 = "(" (is_var2 ? "frame[z." op3 "]" : "z.c") raccessor2 ")"
		gsub(/\$2/, rep2, e_copy)
		gsub(/\$2/, rep2, pre_copy)
		}

	if ( cond_op )
		{
		cond_eval = e
		cond_rep1 = "(" (is_var1 ? "frame[z.v1]" : "z.c") raccessor1 ")"
		cond_op3 = (is_var1 && is_var2) ? "v2" : "v1"
		cond_rep2 = "(" (is_var2 ? "frame[z." cond_op3 "]" : "z.c") raccessor2 ")"

		gsub(/\$1/, cond_rep1, cond_eval)
		gsub(/\$2/, cond_rep2, cond_eval)

		branch_target = "v1";
		if ( is_var1 && is_var2 )
			branch_target = "v3"
		else if ( is_var1 || is_var2 )
			branch_target = "v2"

		cond_eval = "if ( ! (" cond_eval ") ) pc = z." branch_target ";"
		}
	else
		cond_eval = ""

	if ( is_expr_op )
		{
		if ( "*" in op_types )
			{
			gsub(/\$\$/, "frame[z.v1]", e_copy)
			return pre_copy e_copy expr_app
			}

		else if ( index(e_copy, "$$") > 0 )
			{
			gsub(/\$\$/, "frame[z.v1]" laccessor, e_copy)
			return pre_copy e_copy expr_app
			}

		else
			{
			return pre_copy \
				"frame[z.v1]" laccessor " = " e_copy expr_app
			}
		}
	else
		return e_copy raccessor1
	}

function build_op(op, type, sub_type1, sub_type2, orig_eval, eval,
			is_var1, is_var2)
	{
	orig_op = op
	orig_suffix = ""
	gsub(/-/, "_", op)
	upper_op = toupper(op)
	op_type = op type

	full_op = "OP_" upper_op "_" type
	full_op_no_sub = full_op
	if ( sub_type1 && sub_type1 != "X" && sub_type1 != "*" )
		{
		full_op = full_op "_" sub_type1
		orig_suffix = "-" sub_type1

		if ( sub_type2 != sub_type1 )
			{
			full_op = full_op sub_type2
			orig_suffix = orig_suffix sub_type2
			}
		}

	# Track whether this is the "representative" operand for
	# operations with multiple types of operands.  This lets us
	# avoid redundant declarations.
	is_rep = ! sub_type1 || sub_type1 == op_type_rep

	do_vec = vector && ! no_vec[sub_type1] && ! no_vec[sub_type1, sub_type2]

	if ( ary_op == 2 && (! is_var1 || ! is_var2) )
		# We do not support constant operands for binary vector
		# operations.  These have been deprecated ... and if we
		# did, then we would have to figure out how to hold
		# in generated instructions both the type of the constant
		# and the managed type of the vector.
		do_vec = 0

	if ( ! internal_op && is_rep )
		{
		if ( ! (type in args) )
			gripe("bad op type " type " for " op)

		print ("\tvirtual const CompiledStmt " \
			op_type args[type] " = 0;") >base_class_f
		print ("\tconst CompiledStmt " op_type args[type] \
			" override;") >sub_class_f

		if ( do_vec )
			{
			print ("\tvirtual const CompiledStmt " \
				op_type vec args[type] " = 0;") >base_class_f
			print ("\tconst CompiledStmt " op_type vec \
				args[type] " override;") >sub_class_f
			}

		if ( cond_op )
			{
			ct = cond_type[type]

			print ("\tvirtual const CompiledStmt " \
				op_type cond args[ct] " = 0;") >base_class_f
			print ("\tconst CompiledStmt " op_type cond \
				args[ct] " override;") >sub_class_f
			}
		}

	print ("\t" full_op ",") >ops_f
	if ( do_vec )
		print ("\t" full_op vec ",") >ops_f
	if ( cond_op )
		print ("\t" full_op cond ",") >ops_f

	print ("\tcase " full_op ":\treturn \"" tolower(orig_op) \
		"-" type orig_suffix "\";") >ops_names_f
	if ( do_vec )
		print ("\tcase " full_op vec ":\treturn \"" tolower(orig_op) \
			"-" type orig_suffix "-vec" "\";") >ops_names_f
	if ( cond_op )
		print ("\tcase " full_op cond ":\treturn \"" tolower(orig_op) \
			"-" type orig_suffix "-cond" "\";") >ops_names_f

	flavor1 = op1_flavor ? op1_flavor : "OP1_WRITE";
	print ("\t", flavor1 ",\t// " full_op) >op1_flavors_f
	if ( do_vec )
		print ("\t", flavor1 ",\t// " full_op vec) >op1_flavors_f
	if ( cond_op )
		print ("\t", "OP1_READ" ",\t// " full_op cond) >op1_flavors_f

	if ( no_eval )
		print ("\tcase " full_op ":\tbreak;") >ops_eval_f
	else
		print ("\tcase " full_op ":\n\t\t{ " \
			multi_eval eval multi_eval eval_blank \
			"}" multi_eval eval_blank "break;\n") >ops_eval_f

	if ( cond_op )
		{
		# For now we ASSUME that conditionals are binary.

		print ("\tcase " full_op cond ":\n\t\t{ " \
			cond_eval \
			"}" multi_eval eval_blank "break;\n") >ops_eval_f
		}

	if ( do_vec && ! no_eval )
		{
		if ( ary_op == 1 )
			{
			print ("\tcase " full_op vec ":\n\t\tvec_exec(" full_op vec \
				", frame[z.v1].vector_val,\n\t\t\t" \
				(is_var1 ? "frame[z.v2]" : "z.c") \
				".vector_val, &ZAM_VM_bindings);\n\t\tbreak;\n") >ops_eval_f

			oe_copy = orig_eval
			gsub(/\$1/, "vec2[i]" raccessor1, oe_copy)

			print ("\tcase " full_op vec ": vec1[i]" laccessor " = " \
				oe_copy "; break;") >vec1_eval_f
			}

		else if ( is_var1 && is_var2 )
			{
			# Here we rely on the fact that we do not provide
			# compiler support for constants in vector operations.
			# See older history for code that does support this.
			# See comment above for the role of op3.
			print ("\tcase " full_op vec ":\n\t\tvec_exec("  \
				full_op vec ", z.t,\n\t\t" \
				"frame[z.v1].vector_val, " \
				"frame[z.v2].vector_val, " \
				"frame[z.v3].vector_val, " \
				"&ZAM_VM_bindings);\n\t\tbreak;\n") >ops_eval_f

			oe_copy = orig_eval
			gsub(/\$1/, "vec2[i]" raccessor1, oe_copy)
			gsub(/\$2/, "vec3[i]" raccessor2, oe_copy)

			# Check for whether "$$" is meaningful, which
			# occurs for types with non-atomic frame values,
			# and also for any mixed evaluation, but not
			# for conditionals.
			if ( (eval_selector[sub_type1] != "" ||
			      sub_type1 != sub_type2) && ! cond_op )
				{
				gsub(/\$\$/, "vec1[i]" laccessor, oe_copy)
				print ("\tcase " full_op vec ":\n\t\t{\n") >vec2_eval_f
				if ( sub_type1 in is_managed )
					print ("\t\tif ( needs_management ) delete vec1[i]" laccessor ";\n\t\t") >vec2_eval_f
				print (oe_copy "\n\t\tbreak;\n\t\t}") >vec2_eval_f
				}

			else
				print ("\tcase " full_op vec ":\n\t\tvec1[i]" \
					laccessor " = " \
					oe_copy "; break;") >vec2_eval_f
			}
		}

	if ( ! internal_op && is_rep )
		{
		gen_method(full_op_no_sub, full_op, type, sub_type1,
				0, 0, method_pre)

		if ( do_vec )
			gen_method(full_op_no_sub, full_op, type, sub_type1,
					1, 0, method_pre)

		if ( cond_op )
			gen_method(full_op_no_sub, full_op, type, sub_type1,
					0, 1, method_pre)
		}

	if ( assign_op && type in assign_types )
		{
		if ( type == "RV" )
			{
			print ("\tcase EXPR_" upper_op ":\treturn c->" op_type \
				"(lhs, r1->AsNameExpr(), rhs->AsFieldExpr());") >exprsV_f
			}

		else if ( type == "RC" )
			{
			print ("\tcase EXPR_" upper_op ":\treturn c->" op_type \
				"(lhs, r1->AsConstExpr(), rhs->AsFieldExpr());") >exprsC1_f
			}

		else if ( type == "XV" )
			{
			print ("\tcase EXPR_" upper_op ":\treturn c->" op_type \
				"(lhs, r1->AsNameExpr());") >exprsV_f
			}

		else if ( type == "XC" )
			{
			print ("\tcase EXPR_" upper_op ":\treturn c->" op_type \
				"(lhs, r1->AsConstExpr());") >exprsC1_f
			}

		else
			{
			# Note, no need to generate these for FV/FC types
			# because FieldLHSAssignExpr does its own dispatch.
			}
		}

	else if ( type == "Ri" )
		{
		print ("\tcase EXPR_" upper_op ":\treturn c->" op_type \
			"(lhs, r1->AsNameExpr(), rhs->AsHasFieldExpr()->Field());") >exprsV_f
		}

	else if ( expr_op && is_rep )
		{
		if ( type == "C" )
			gripe("bad type " type " for expr " op)

		expr_case = "EXPR_" upper_op

		if ( type in exprC1 )
			{
			eargs = exprC1[type]
			f = exprsC1_f
			}

		else if ( type in exprC2 )
			{
			eargs = exprC2[type]
			f = exprsC2_f
			}

		else if ( type in exprC3 )
			{
			eargs = exprC3[type]
			f = exprsC3_f
			}

		else if ( type in exprV )
			{
			eargs = exprV[type]
			f = exprsV_f
			}

		else
			gripe("bad type " type " for expr " op)

		if ( do_vec )
			{
			print ("\tcase " expr_case ":\n\t\t" \
				"if ( rt->Tag() == TYPE_VECTOR )\n\t\t\t" \
				"return c->" op_type vec "(" eargs ");\n" \
				"\t\telse\n\t\t\t" \
				"return c->" op_type "(" eargs ");") >f
			}

		else
			print ("\tcase " expr_case ":\treturn c->" \
				op_type "(" eargs ");") >f

		# The test on "type" in the following is to ensure we
		# generate the case only once per operator, rather than
		# once for each type.
		if ( cond_op && type == "VVV" )
			{
			print ("\tcase " expr_case ":\n\t\t" \
				"if ( n1 && n2 )\n\t\t\t" \
				"return " op "VVV" cond "(n1, n2, 0);\n" \
				"\t\telse if ( n1 )\n\t\t\t" \
				"return " op "VVC" cond "(n1, c, 0);\n" \
				"\t\telse\n\t\t\t" \
				"return " op "VCV" cond "(c, n2, 0);\n") >conds_f
			}
		}
	}

function gen_method(full_op_no_sub, full_op, type, sub_type, is_vec, is_cond, method_pre)
	{
	mt = is_cond ? cond_type[type] : type
	suffix = is_vec ? vec : (is_cond ? cond : "")

	print ("const CompiledStmt ZAM::" \
		(op_type suffix) args[mt]) >methods_f

	print ("\t{") >methods_f

	if ( custom_method )
		{
		cm_copy = custom_method
		gsub(/\$\*/, args2[mt], cm_copy)
		print ("\t" cm_copy) >methods_f
		# This { balances the following one so searches for matching
		# braces are not thrown off.
		print ("\t}\n") >methods_f
		return
		}

	if ( method_pre )
		print ("\t" method_pre ";") >methods_f

	if ( mt == "O" || mt == "VO" )
		{
		pre_arg = mt == "O" ? "" : ", Frame1Slot(n, " full_op ")"
		print ("\treturn AddInst(ZInst(" \
			full_op pre_arg ", reg));") >methods_f
		}

	else if ( mt == "R" )
		{
		print ("\tauto z = GenInst(this, " full_op ", " \
			args2[mt] ");") >methods_f
		print ("\tz.e = n1;") >methods_f
		print ("\tz.t = n1->Type().get();") >methods_f
		print ("\tz.CheckIfManaged(z.t);") >methods_f
		print ("\treturn AddInst(z);") >methods_f
		}

	else if ( args2[mt] != "" )
		{
		if ( sub_type && sub_type != "X" )
			indent = "\t\t"
		else
			indent = "\t"

		# This is the only scenario where sub_type should occur.
		part1 = indent "auto z = GenInst(this, "

		part2a = ", " args2[mt] ");\n"
		part2c = indent "return AddInst(z);"

		if ( is_vec && ary_op == 2 )
			part2c = indent "z.t = myt;\n" part2c

		# Provide access to the individual variables.
		split(args2[mt], vars, /, /)

		if ( set_type )
			{
			# Remove extraneous $, if present.
			sub(/\$/, "", set_type)

			part2b = indent "z.t = " vars[set_type] "->Type().get();\n"
			}
		else
			part2b = ""

		if ( set_expr )
			{
			# Remove extraneous $, if present.
			sub(/\$/, "", set_expr)

			part2b = part2b indent "z.e = " vars[set_expr] ";\n"
			}

		part2 = part2a part2b part2c

		if ( sub_type && sub_type != "X" )
			{
			# Need braces for multi-line parts.
			part1 = indent "{\n" part1
			part2 = part2 "\n" indent "}"

			# Figure out the type to use to select which
			# flavor of the operation to generate.  For
			# operations with three operands, select the
			# second operand, not the first, in order to
			# generate correct typing for relationals (where
			# the first operand has a type of bool regardless
			# of the types of the other operands).

			if ( is_cond )
				{
				if ( mt == "VVi" )
					test_var = "n1"
				else
					test_var = "c"
				}
			else
				{
				op2_is_const = mt ~ /^VC/

				if ( mt ~ /^.../ || type_selector == 2 )
					# Has three operands, choose second.
					test_var = op2_is_const ? "c" : "n2"
				else if ( op2_is_const )
					test_var = "c"
				else
					test_var = "n1"
				}

			print ("\tauto t = " test_var "->Type().get();") >methods_f

			if ( is_vec )
				{
				print ("\tt = t->AsVectorType()->YieldType();") >methods_f
				if ( ary_op == 2 )
					{
					print ("\tauto yt1 = n1->Type()->AsVectorType()->YieldType();") >methods_f
					print ("\tauto myt = IsManagedType(yt1) ? yt1 : nullptr;") >methods_f
					}
				}

			print ("\tauto tag = t->Tag();") >methods_f
			print ("\tauto i_t = t->InternalType();") >methods_f

			n = 0
			default_seen = 0
			for ( o in op_types )
				{
				if ( is_vec && no_vec[o] )
					continue

				if ( o == "*" )
					{
					++default_seen

					build_method_conditional(o, ++n)
					print (part1 full_op_no_sub part2) >methods_f
					continue
					}

				invoke1 = (part1 full_op_no_sub "_")
				invoke2 = ((is_vec ? vec : (is_cond ? cond : "")) part2)

				build_method_conditional(o, ++n)
				print (invoke1 o invoke2) >methods_f
				}

			if ( mix_eval )
				{
				# To date, there are few of these, and only
				# one per op, so we just do them by hand.
				#
				# We do not support vectors for these,
				# even though the interpreter does.
				if ( is_cond )
					{
					# We fudge and treat the actual
					# first operand as "op2" here, etc.,
					# so that we can integrate with
					# the code for operator assignment.
					if ( mt == "VVi" )
						{
						op2_param = "n1"
						op3_param = "n2"
						}
					else if ( mt == "CVi" )
						{
						op2_param = "c"
						op3_param = "n"
						}
					else
						{
						op2_param = "n"
						op3_param = "c"
						}
					}
				else
					{
					op2_param = op2_is_const ? "c" : "n2";
					op3_is_const = mt ~ /^V.C/
					op3_param = op2_is_const ? "n2" : (op3_is_const ? "c" : "n3")
					}

				op2_tag = op2_param "->Type()->Tag()"
				op3_tag = op3_param "->Type()->Tag()"

				if ( ! ((ev_mix1 SUBSEP ev_mix2) in mixed_type_supported) )
					gripe("unsupported eval-mixed")

				if ( ev_mix1 == "P" )
					print ("\t" else_text "if ( " op2_tag " == TYPE_PATTERN && " op3_tag " == TYPE_STRING )") >methods_f
				else
					print ("\t" else_text "if ( " op2_tag " == TYPE_ADDR && " op3_tag " == TYPE_INT )") >methods_f

				mix_suffix = "_" ev_mix1 ev_mix2
				print ("\t" part1 (full_op_no_sub mix_suffix) \
					part2) >methods_f
				}

			if ( ! default_seen )
				print ("\telse\n\t\treporter->InternalError(\"bad internal type\");") >methods_f
			}
		else
			print (part1 full_op part2) >methods_f
		}
	else
		print ("\treturn AddInst(GenInst(this, \
			" full_op "));") >methods_f

	print ("\t}\n") >methods_f
	}

function build_method_conditional(o, n)
	{
	else_text = (n > 1) ? "else " : "";
	if ( o == "*" )
		print ("\t" else_text ) >methods_f
	else
		{
		test = method_map[o]
		print ("\t" else_text "if ( " test " )") >methods_f
		}
	}

function clear_vars()
	{
	opaque = set_expr = set_type = type = type_selector = operand_type = ""
	op_type_rep = custom_method = method_pre = eval_pre = ""
	no_const = no_eval = mix_eval = multi_eval = eval_blank = ""
	cond_op = rel_op = ary_op = assign_op = expr_op = op = ""
	vector = binary_op = internal_op = ""
	op1_flavor = direct_method = direct_op = ""
	laccessor = raccessor1 = raccessor2 = ""
	op1_accessor = op2_accessor = ""
	ev_mix1 = ev_mix2 = ""

	delete eval
	delete op_types
	}

function prep(f)
	{
	print ("\t{") >f
	print ("\tswitch ( rhs->Tag() ) {") >f
	}

function finish(f, which)
	{
	print ("\tdefault:") >f
	print ("\t\treporter->InternalError(\"inconsistency in " which " AssignExpr::Compile: %s\", obj_desc(rhs));") >f
	print ("\t}\t}") >f
	}

function finish_default_ok(f)
	{
	print ("\tdefault:\tbreak;") >f
	}

function gripe(msg)
	{
	print "error at input line", NR ":", msg
	exit(1)
	}
' $*
