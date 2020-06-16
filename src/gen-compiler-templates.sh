#! /bin/sh

gawk '
BEGIN	{
	base_class_f = add_file("CompilerBaseDefs.h")
	exprsC1_f = add_file("CompilerOpsExprsDefsC1.h")
	exprsC2_f = add_file("CompilerOpsExprsDefsC2.h")
	exprsC3_f = add_file("CompilerOpsExprsDefsC3.h")
	exprsV_f = add_file("CompilerOpsExprsDefsV.h")

	fieldsC1_f = add_file("CompilerOpsFieldsDefsC1.h")
	fieldsC2_f = add_file("CompilerOpsFieldsDefsC2.h")
	fieldsV_f = add_file("CompilerOpsFieldsDefsV.h")

	conds_f = add_file("ZAM-Conds.h")
	sub_class_f = add_file("ZAM-SubDefs.h")
	ops_f = add_file("ZAM-OpsDefs.h")
	ops_names_f = add_file("ZAM-OpsNamesDefs.h")
	op1_flavors_f = add_file("ZAM-Op1FlavorsDefs.h")
	ops_direct_f = add_file("CompilerOpsDirectDefs.h")
	ops_eval_f = add_file("ZAM-OpsEvalDefs.h")
	vec1_eval_f = add_file("ZAM-Vec1EvalDefs.h")
	vec2_eval_f = add_file("ZAM-Vec2EvalDefs.h")
	methods_f = add_file("ZAM-OpsMethodsDefs.h")

	prep(exprsC1_f)
	prep(exprsC2_f)
	prep(exprsC3_f)
	prep(exprsV_f)

	prep(fieldsC1_f)
	prep(fieldsC2_f)
	prep(fieldsV_f)

	args["X"] = "()"
	args["O"] = "(OpaqueVals* v)"
	args["Ri"] = "(const NameExpr* n1, const NameExpr* n2, int field)"
	args["Rii"] = "(const NameExpr* n1, const NameExpr* n2, int field1, int field2)"
	args["V"] = "(const NameExpr* n)"
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

	args["Vi"] = "(const NameExpr* n, int i)"
	args["CVi"] = "(const ConstExpr* c, const NameExpr* n, int i)"
	args["VVi"] = "(const NameExpr* n1, const NameExpr* n2, int i)"
	args["VCi"] = "(const NameExpr* n, const ConstExpr* c, int i)"
	args["VVii"] = "(const NameExpr* n1, const NameExpr* n2, int i1, int i2)"
	args["VCii"] = "(const NameExpr* n, const ConstExpr* c, int i1, int i2)"
	args["VCV"] = "(const NameExpr* n1, const ConstExpr* c, const NameExpr* n2)"
	args["VVVi"] = "(const NameExpr* n1, const NameExpr* n2, const NameExpr* n3, int i)"
	args["VCVi"] = "(const NameExpr* n1, const ConstExpr* c, const NameExpr* n2, int i)"
	args["VVCi"] = "(const NameExpr* n1, const NameExpr* n2, const ConstExpr* c, int i)"

	args["VLV"] = "(const NameExpr* n1, const ListExpr* l, const NameExpr* n2)"
	args["VLC"] = "(const NameExpr* n, const ListExpr* l, const ConstExpr* c)"
	args["VVL"] = "(const NameExpr* n1, const NameExpr* n2, const ListExpr* l)"
	args["ViHL"] = "(const NameExpr* n, int i, EventHandler* h, const ListExpr* l)"
	args["CiHL"] = "(const ConstExpr* c, int i, EventHandler* h, const ListExpr* l)"

	args2["X"] = ""
	args2["O"] = "reg"
	args2["Ri"] = "n1, n2, field"
	args2["Rii"] = "n1, n2, field1, field2"
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
	args2["VVVi"] = "n1, n2, n3, i"
	args2["VCVi"] = "n1, c, n2, i"
	args2["VVCi"] = "n1, n2, c, i"

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

	field_exprC1["VC"] = "lhs, r1->AsConstExpr(), field";
	field_exprC1["VCV"] = "lhs, r1->AsConstExpr(), r2->AsNameExpr(), field"
	field_exprC2["VVC"] = "lhs, r1->AsNameExpr(), r2->AsConstExpr(), field"
	field_exprV["VV"] = "lhs, r1->AsNameExpr(), field"
	field_exprV["VVV"] = "lhs, r1->AsNameExpr(), r2->AsNameExpr(), field"

	accessors["i"] = accessors["I"] = ".int_val"
	accessors["u"] = accessors["U"] = ".uint_val"
	accessors["d"] = accessors["D"] = ".double_val"

	accessors["?"] = ".any_val"
	accessors["A"] = ".addr_val"
	accessors["F"] = ".func_val"
	accessors["f"] = ".file_val"
	accessors["L"] = ".list_val"
	accessors["N"] = ".subnet_val"
	accessors["O"] = ".opaque_val"
	accessors["P"] = ".re_val"
	accessors["R"] = ".record_val"
	accessors["S"] = ".string_val"
	accessors["T"] = ".table_val"
	accessors["t"] = ".type_val"
	accessors["V"] = ".vector_val"
	accessors["X"] = "###"

	# 1 = managed via new/delete, 2 = managed via Ref/Unref.
	# Currently we only use type 2, but keep support for type 1
	# just in case we want to make further changes.
	is_managed["V"] = 2	# vector
	is_managed["A"] = 2	# addr
	is_managed["f"] = 2	# file
	is_managed["F"] = 2	# function
	is_managed["L"] = 2	# list
	is_managed["N"] = 2	# subnet
	is_managed["O"] = 2	# opaque
	is_managed["P"] = 2	# pattern
	is_managed["R"] = 2	# record
	is_managed["S"] = 2	# string
	is_managed["T"] = 2	# table
	is_managed["t"] = 2	# type

	# We leave out "any" because we special-case it.
	# is_managed["?"] = 2	# any

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

	# Assignments to record fields "x$f = y".  The type should be that
	# of "x$f", and is used to select the correct assignment sequence.
	args["FV"] = "(const NameExpr* n1, int field, const BroType* t, const NameExpr* n2)"
	args["FC"] = "(const NameExpr* n, int field, const BroType* t, const ConstExpr* c)"

	# Same for "x$f = y$g".
	args["FFV"] = "(const NameExpr* n1, int f1, const BroType* t, const NameExpr* n2, int f2)"
	args["FFC"] = "(const NameExpr* n, int f1, const BroType* t, const ConstExpr* c, int f2)"

	# Vanilla assignments "x=y".
	args["XV"] = "(const NameExpr* n1, const NameExpr* n2)"
	args["XC"] = "(const NameExpr* n, const ConstExpr* c)"

	args2["RV"] = "n1, n2, field"
	args2["RC"] = "n, c, field"
	args2["FV"] = "n1, n2, field"
	args2["FFV"] = "n1, n2, f1, f2"
	args2["FC"] = "n, c, field"
	args2["FFC"] = "n, c, f1, f2"
	args2["XV"] = "n1, n2"
	args2["XC"] = "n, c"

	# Indexed by assignment type
	method_extra_prefix["R"] = "auto field = f->Field();"

	# For an assign-to-any, then we will need the instruction
	# type field set to the type of the RHS.  It does no harm
	# to just always do that.
	method_extra_suffix["R"] = "z.SetType($2->Type()->AsRecordType()->FieldType(field));"
	method_extra_suffix["X"] = "z.SetType(t);"

	# Whether for generated statements to take their type from the
	# main assignment target (1) or from the first operand (0).
	use_target_for_type["F"] = 0
	use_target_for_type["R"] = 1
	use_target_for_type["X"] = 0

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

	# Templates for mapping "bare" frame assignments (type 1 management)
	# to specific transformations/memory management, depending on the type
	# of the assignment.  Indexed by both the type and 0/1 for short/long.

	assign_tmpl["ANY", SHORT] = "ZAMValUnion $$ = $1;"
	assign_tmpl["", SHORT] = "ZAMValUnion $$ = $1;"

	assign_tmpl["ANY", LONG] = "$$.any_val = $1.ToVal(z.t).release();"
	assign_tmpl["", LONG] = "$$ = $1;"

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
	method_map["S"] = "i_t == TYPE_INTERNAL_STRING"

	method_map["F"] = "tag == TYPE_FUNC"
	method_map["L"] = "tag == TYPE_LIST"
	method_map["O"] = "tag == TYPE_OPAQUE"
	method_map["P"] = "tag == TYPE_PATTERN"
	method_map["R"] = "tag == TYPE_RECORD"
	method_map["T"] = "tag == TYPE_TABLE"
	method_map["f"] = "tag == TYPE_FILE"
	method_map["t"] = "tag == TYPE_TYPE"

	# We need to explicitly check for any/not-any because we go through
	# the op-types via dictionary traversal (i.e., unpredcitable order).
	method_map["V"] = "tag == TYPE_VECTOR"

	# Maps original op-types (for example, for unary or binary
	# expressions) to the equivalent when using them in a field assignment.
	field_type["Ri"] = "Rii"
	field_type["VC"] = "VCi"
	field_type["VV"] = "VVi"
	field_type["VVV"] = "VVVi"
	field_type["VCV"] = "VCVi"
	field_type["VVC"] = "VVCi"

	# Where in an instruction the constant associated with the field
	# offset resides.  This is always the last 'v' slot.
	field_offset["Rii"] = 3
	field_offset["VCi"] = 2
	field_offset["VVi"] = 3
	field_offset["VVVi"] = 4
	field_offset["VCVi"] = 3
	field_offset["VVCi"] = 3

	# Maps original op-types (for example, for relationals) to the
	# equivalent when using them in a conditional.
	cond_type["VVV"] = "VVi"
	cond_type["VVC"] = "VCi"
	cond_type["VCV"] = "CVi"

	++mixed_type_supported["P", "S"]
	++mixed_type_supported["A", "I"]

	# Suffices used for field/vector/conditional operations.
	field = "_field"
	vec = "_vec"
	cond = "_cond"
	}

$1 == "op"	{ dump_op(); op = $2; next }
$1 == "expr-op"	{ dump_op(); op = $2; expr_op = 1; field_op = 1; next }
$1 == "assign-op" { dump_op(); op = $2; assign_op = 1; next }
$1 == "unary-op"	{ dump_op(); op = $2; ary_op = 1; next }
$1 == "direct-unary-op" {
	dump_op(); op = $2; direct_method = $3; direct_op = 1; next
	}
$1 == "unary-expr-op"	{
	dump_op(); op = $2; expr_op = 1; field_op = 1; ary_op = 1; next
	}
$1 == "binary-expr-op"	{
	dump_op(); op = $2; expr_op = 1; field_op = 1; ary_op = 2; next
	}
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

$1 == "field-op"	{ field_op = 1; next }
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

	finish(exprsC1_f, "C1", 0)
	finish(exprsC2_f, "C2", 0)
	finish(exprsC3_f, "C3", 0)
	finish(exprsV_f, "V", 0)

	finish(fieldsC1_f, "C1", 1)
	finish(fieldsC2_f, "C2", 1)
	finish(fieldsV_f, "V", 1)

	finish_default_ok(ops_direct_f)

	for ( i = 1; i <= nfiles; ++i )
		close(files[i])
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
				this_type = "V" op1

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
					ex = expand_eval(esel, eval_pre,
							this_type, expr_op,
							i, i, j, 0)
					}

				build_op(op, this_type, i, i, esel, ex, j, 0)
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

	this_type = "V" op1 op2

	for ( i in op_types )
		{
		sel = eval_selector[i]
		ex = expand_eval(eval[sel], eval_pre, this_type, expr_op, i, i, j, k)
		build_op(op, this_type, i, i, eval[sel], ex, j, k)
		}

	if ( mix_eval )
		{
		ex = expand_eval(mix_eval, eval_pre, this_type, expr_op, ev_mix1, ev_mix2, j, k)
		build_op(op, this_type, ev_mix1, ev_mix2, mix_eval, ex, j, k)
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
	build_assignment_dispatch3(op, type, is_var, 0)
	if ( type == "F" )
		build_assignment_dispatch3(op, type, is_var, 1)
	}

function build_assignment_dispatch3(op, type, is_var, is_field)
	{
	# Generate generic versions of the assignment, which provide custom
	# methods for dispatching to the specific flavors.
	no_eval = 1

	targ = is_var ? "n1" : "n"
	rhs_op = is_var ? "n2" : "c"
	type_base = use_target_for_type[type] ? targ : rhs_op

	atype = type (is_field ? "F" : "") (is_var ? "V" : "C")

	if ( type == "F" )
		{
		# t is passed into field-assignment methods
		custom_method = ""
		any_cond_targ = "t"
		}
	else
		{
		custom_method = "auto t = " type_base "->Type().get();\n\t"
		any_cond_targ = targ "->Type()"
		}

	custom_method = custom_method \
		"auto tag = t->Tag();\n" \
		"\tauto i_t = t->InternalType();\n" \
		"\tZInst z;"

	if ( type in method_extra_prefix )
		custom_method = custom_method "\n\t" method_extra_prefix[type]

	# Do the "ANY" case first, since it is dispatched on the type of n1
	# rather than n2 (other than for record field assignments).
	custom_method = custom_method "\n\t" \
		build_assign_case(op, atype, "ANY", any_cond_targ "->Tag() == TYPE_ANY", is_var, is_field)

	for ( flavor in is_managed )
		custom_method = custom_method \
			build_assign_case(op, atype, flavor, method_map[flavor], is_var, is_field)

	# Add the default case.
	custom_method = custom_method "\n" build_assign_case(op, atype, "", "", is_var, is_field)

	if ( type in method_extra_suffix )
		{
		xtra = method_extra_suffix[type]
		gsub(/\$2/, rhs_op, xtra)
		custom_method = custom_method "\n\t" xtra
		}

	custom_method = custom_method "\n" \
		"\tz.e = " rhs_op ";\n" \
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
	build_assignment3(op, type, flavor, is_var, 0, ev)
	if ( type == "F" )
		build_assignment3(op, type, flavor, is_var, 1, ev)
	}

function build_assignment3(op, type, flavor, is_var, is_field, ev)
	{
	if ( index(ev, "@") == 0 )
		gripe("no @ specifier in assignment op")

	assign_val = ev
	sub(/.*@/, "", assign_val)
	sub(/[ \t;].*/, "", assign_val)

	a_t = assignment_type[type]

	if ( is_field )
		{
		tmpl = "auto $$ = $2;\n\t\t"

		if ( flavor in is_managed && is_managed[flavor] == 2 )
			tmpl = tmpl "::Ref(v" accessors[flavor] ");\n\t\t"

		tmpl = tmpl \
			"if ( ZAM_error ) z.e->RuntimeError(\"field value missing\");\n\t\t" \
			"else // kill auto-semicolon"
		}

	else if ( ! (flavor in is_managed) || is_managed[flavor] == 1 )
		tmpl = assign_tmpl[flavor, a_t]

	else if ( is_managed[flavor] == 2 )
		{
		if ( a_t == SHORT )
			tmpl = "::Ref($1" accessors[flavor] ");\n" \
				"\t\tZAMValUnion $$ = $1"
		else
			{
			lhs = "$$" accessors[flavor]
			rhs = "$1" accessors[flavor]
			tmpl = "\t\t::Ref(" rhs ");\n" \
			"\t\tUnref(" lhs ");\n" \
				"\t\t" lhs " = " rhs ";\n"
			}
		}
	else
		gripe("missing is_managed " flavor " " (flavor in is_managed) " " is_managed[flavor])

	if ( a_t == LONG )
		# Allow for long form to be for example in an if-else
		# clause.  We do not do this for SHORT however because
		# for it the whole point is that the $$ variable is
		# subsequently accessible.
		tmpl = "{\n" tmpl "\n}"

	gsub(/\$1/, assign_val, tmpl)
	gsub(/\$\$/, a_t ? "frame[z.v1]" : "v", tmpl)

	gsub(/@[a-zA-Z$0-9]*/, tmpl, ev)

	rhs = is_var ? "frame[z.v2]" : "z.c"
	lhs_field = is_var ? "z.v3" : "z.v2"

	if ( a_t == SHORT && is_field )
		{
		rhs_field = is_var ? "z.v4" : "z.v3"
		rhs = rhs ".record_val->RawFields()->Lookup(" rhs_field ", ZAM_error)"
		}

	gsub(/\$2/, rhs, ev)
	gsub(/\$3/, lhs_field, ev)

	op_tag = "V" (is_var ? "V" : "C")
	if ( is_field )
		# Add on room for the second field.
		op_tag = op_tag "i"

	build_op(op, op_tag "i", flavor, "", ev, ev, is_var, 0)
	}

function build_assign_case(op, atype, flavor, cond, is_var, is_field)
	{
	targ = is_var ? "n1" : "n"
	operand = is_var ? "n2" : "c"

	full_op = "OP_" toupper(op) "_V" (is_var ? "V" : "C") "i"
	if ( is_field )
		full_op = full_op "i"

	gsub(/-/, "_", full_op)

	assign_args = args2[atype]

	if ( ! flavor )
		return "\t\tz = GenInst(this, " full_op ", " assign_args ");"

	full_op = full_op "_" flavor

	return "if ( " cond " )\n" \
		"\t\tz = GenInst(this, " full_op ", " assign_args ");\n" \
		"\telse "
	}

function expand_eval(e, pre_eval, this_type, is_expr_op, otype1, otype2, is_var1, is_var2)
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

		cond_eval = "if ( ! (" cond_eval ") ) { pc = z." branch_target "; continue; }"
		}
	else
		cond_eval = ""

	if ( is_expr_op )
		{
		if ( field_op && this_type in field_type )
			{
			ft = field_type[this_type]
			fo = field_offset[ft]
			field_accessor = "frame[z.v1].record_val->RawFields()->SetField(z.v" fo ")"

			# Note, in the following we do work even if field_op
			# is not set, because it is simpler than having a
			# bunch of conditionals.
			}

		if ( "*" in op_types )
			{
			e_copy = pre_copy e_copy expr_app
			field_eval = e_copy

			gsub(/\$\$/, "frame[z.v1]", e_copy)
			gsub(/\$\$/, field_accessor, field_eval)

			return pre_copy e_copy expr_app
			}

		else if ( index(e_copy, "$$") > 0 )
			{
			e_copy = pre_copy e_copy expr_app
			field_eval = e_copy

			gsub(/\$\$/, "frame[z.v1]" laccessor, e_copy)
			gsub(/\$\$/, field_accessor laccessor, field_eval)

			return e_copy
			}

		else
			{
			field_eval = pre_copy field_accessor laccessor \
				" = " e_copy expr_app

			e_copy = pre_copy "frame[z.v1]" laccessor \
				" = " e_copy expr_app

			return e_copy
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

	if ( is_rep && field_op )
		{
		if ( ! (type in field_type) || no_eval )
			field_op = ""
		}

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

		if ( field_op )
			{
			ft = field_type[type]
			print ("\tvirtual const CompiledStmt " \
				op_type field args[ft] " = 0;") >base_class_f
			print ("\tconst CompiledStmt " op_type field \
				args[ft] " override;") >sub_class_f
			}

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
	if ( field_op )
		print ("\t" full_op field ",") >ops_f
	if ( do_vec )
		print ("\t" full_op vec ",") >ops_f
	if ( cond_op )
		print ("\t" full_op cond ",") >ops_f

	print ("\tcase " full_op ":\treturn \"" tolower(orig_op) \
		"-" type orig_suffix "\";") >ops_names_f
	if ( field_op )
		print ("\tcase " full_op field ":\treturn \"" tolower(orig_op) \
			"-" type orig_suffix "-field" "\";") >ops_names_f
	if ( do_vec )
		print ("\tcase " full_op vec ":\treturn \"" tolower(orig_op) \
			"-" type orig_suffix "-vec" "\";") >ops_names_f
	if ( cond_op )
		print ("\tcase " full_op cond ":\treturn \"" tolower(orig_op) \
			"-" type orig_suffix "-cond" "\";") >ops_names_f

	flavor1 = op1_flavor ? op1_flavor : "OP1_WRITE";
	print ("\t", flavor1 ",\t// " full_op) >op1_flavors_f
	if ( field_op )
		print ("\t", flavor1 ",\t// " full_op field) >op1_flavors_f
	if ( do_vec )
		print ("\t", flavor1 ",\t// " full_op vec) >op1_flavors_f
	if ( cond_op )
		print ("\t", "OP1_READ" ",\t// " full_op cond) >op1_flavors_f

	if ( no_eval )
		print ("\tcase " full_op ":\tbreak;") >ops_eval_f
	else
		{
		print ("\tcase " full_op ":\n\t\t{ " \
			multi_eval eval multi_eval eval_blank \
			"}" multi_eval eval_blank "break;\n") >ops_eval_f

		if ( field_op )
			print ("\tcase " full_op field ":\n\t\t{ " \
				multi_eval field_eval multi_eval eval_blank \
				"}" multi_eval eval_blank "break;\n") >ops_eval_f
		}

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
				".vector_val);\n\t\tbreak;\n") >ops_eval_f

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
				"frame[z.v3].vector_val);\n\t\tbreak;\n") >ops_eval_f

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
					print ("\t\tif ( needs_management ) Unref( vec1[i]" laccessor ");\n\t\t") >vec2_eval_f
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
				0, 0, 0, method_pre)

		if ( field_op )
			gen_method(full_op_no_sub, full_op, type, sub_type1,
					1, 0, 0, method_pre)

		if ( do_vec )
			gen_method(full_op_no_sub, full_op, type, sub_type1,
					0, 1, 0, method_pre)

		if ( cond_op )
			gen_method(full_op_no_sub, full_op, type, sub_type1,
					0, 0, 1, method_pre)
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

	else if ( type == "Ri" || type == "Rii" )
		{
		print ("\tcase EXPR_" upper_op ":\treturn c->" op_type \
			"(lhs, r1->AsNameExpr(), rhs->AsHasFieldExpr()->Field());") >exprsV_f

		if ( field_op )
			print ("\tcase EXPR_" upper_op ":\treturn c->" op_type \
				field \
				"(lhs, r1->AsNameExpr(), rhs->AsHasFieldExpr()->Field(), field);") >fieldsV_f
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
			ff = fieldsV_f
			}

		else
			gripe("bad type " type " for expr " op)


		if ( field_op )
			{
			if ( type in field_exprC1 )
				{
				feargs = field_exprC1[type]
				ff = fieldsC1_f
				}

			else if ( type in field_exprC2 )
				{
				feargs = field_exprC2[type]
				ff = fieldsC2_f
				}

			else if ( type in field_exprV )
				{
				feargs = field_exprV[type]
				ff = fieldsV_f
				}

			else
				gripe("bad field type " type " " type " for expr " op)
			}

		if ( do_vec )
			print ("\tcase " expr_case ":\n\t\t" \
				"if ( rt->Tag() == TYPE_VECTOR )\n\t\t\t" \
				"return c->" op_type vec "(" eargs ");\n" \
				"\t\telse\n\t\t\t" \
				"return c->" op_type "(" eargs ");") >f
		else
			print ("\tcase " expr_case ":\treturn c->" \
				op_type "(" eargs ");") >f

		if ( field_op )
			print ("\tcase " expr_case ":\treturn c->" \
				op_type field "(" feargs ");") >ff

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

function gen_method(full_op_no_sub, full_op, type, sub_type, is_field, is_vec, is_cond, method_pre)
	{
	mt = type

	if ( is_field )
		mt = field_type[mt]
	else if ( is_cond )
		mt = cond_type[mt]

	suffix = ""
	if ( is_field )
		suffix = field
	else if ( is_vec )
		suffix = vec
	else if ( is_cond )
		suffix = cond

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
		print ("\tz.SetType(n1->Type());") >methods_f
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
			part2c = indent "z.SetType(myt);\n" part2c

		# Provide access to the individual variables.
		split(args2[mt], vars, /, /)

		if ( set_type )
			{
			# Remove extraneous $, if present.
			sub(/\$/, "", set_type)

			part2b = indent "z.SetType(" vars[set_type] "->Type());\n"
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
				# First do types other than default.
				if ( o == "*" )
					{
					default_seen = 1
					continue
					}

				if ( is_vec && no_vec[o] )
					continue

				invoke1 = (part1 full_op_no_sub "_")

				if ( is_field )
					invoke2 = field
				else if ( is_vec )
					invoke2 = vec
				else if ( is_cond )
					invoke2 = cond
				else
					invoke2 = ""

				invoke2 = invoke2 part2

				build_method_conditional(o, ++n)
				print (invoke1 o invoke2) >methods_f
				}

			# Now do the default.
			if ( default_seen )
				{
				build_method_conditional("*", ++n)
				print (part1 full_op_no_sub part2) >methods_f
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
			print (part1 full_op suffix part2) >methods_f
		}
	else
		print ("\treturn AddInst(GenInst(this, " \
			full_op "));") >methods_f

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
	no_const = op_type_rep = custom_method = method_pre = eval_pre = ""
	field_eval = no_eval = mix_eval = multi_eval = eval_blank = ""
	field_op = cond_op = rel_op = ary_op = assign_op = expr_op = op = ""
	vector = binary_op = internal_op = ""
	op1_flavor = direct_method = direct_op = ""
	laccessor = raccessor1 = raccessor2 = ""
	op1_accessor = op2_accessor = ""
	ev_mix1 = ev_mix2 = ""

	delete eval
	delete op_types
	}

function add_file(fn)
	{
	files[++nfiles] = fn
	return fn
	}

function prep(f)
	{
	print ("\t{") >f
	print ("\tswitch ( rhs->Tag() ) {") >f
	}

function finish(f, which, is_field)
	{
	print ("\tdefault:") >f
	print ("\t\treporter->InternalError(\"inconsistency in " which \
		(is_field ? " field" : "") " assignment: %s\", obj_desc(rhs));") >f
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
