#! /bin/sh

awk '
BEGIN	{
	base_class_f = "CompilerBaseDefs.h"
	sub_class_f = "CompilerSubDefs.h"
	ops_f = "CompilerOpsDefs.h"
	ops_names_f = "CompilerOpsNamesDefs.h"
	ops_direct_f = "CompilerOpsDirectDefs.h"
	ops_eval_f = "CompilerOpsEvalDefs.h"
	vec1_eval_f = "CompilerVec1EvalDefs.h"
	vec2_eval_f = "CompilerVec2EvalDefs.h"
	methods_f = "CompilerOpsMethodsDefs.h"
	exprsC1_f = "CompilerOpsExprsDefsC1.h"
	exprsC2_f = "CompilerOpsExprsDefsC2.h"
	exprsC3_f = "CompilerOpsExprsDefsC3.h"
	exprsV_f = "CompilerOpsExprsDefsV.h"

	prep(exprsC1_f)
	prep(exprsC2_f)
	prep(exprsC3_f)
	prep(exprsV_f)

	args["X"] = "()"
	args["O"] = "(OpaqueVals* v)"
	args["R"] = "(const NameExpr* n1, const NameExpr* n2, const FieldExpr* f)"
	args["Ri"] = "(const NameExpr* n1, const NameExpr* n2, int field)"
	args["V"] = "(const NameExpr* n)"
	args["Vi"] = "(const NameExpr* n, int i)"
	args["VV"] = "(const NameExpr* n1, const NameExpr* n2)"
	args["VO"] = "(const NameExpr* n, OpaqueVals* v)"
	args["HL"] = "(EventHandler* h, const ListExpr* l)"
	args["VVV"] = "(const NameExpr* n1, const NameExpr* n2, const NameExpr* n3)"
	args["VVVV"] = "(const NameExpr* n1, const NameExpr* n2, const NameExpr* n3, const NameExpr* n4)"
	args["C"] = "(const ConstExpr* c)"
	args["VC"] = "(const NameExpr* n, ConstExpr* c)"
	args["VVC"] = "(const NameExpr* n1, const NameExpr* n2, ConstExpr* c)"
	args["VVVC"] = "(const NameExpr* n1, const NameExpr* n2, const NameExpr* n3, ConstExpr* c)"
	args["VVCV"] = "(const NameExpr* n1, const NameExpr* n2, ConstExpr*c, const NameExpr* n3)"
	args["VVi"] = "(const NameExpr* n1, const NameExpr* n2, int i)"
	args["VCi"] = "(const NameExpr* n, const ConstExpr* c, int i)"
	args["VCV"] = "(const NameExpr* n1, ConstExpr* c, const NameExpr* n2)"

	args["VLV"] = "(const NameExpr* n1, const ListExpr* l, const NameExpr* n2)"
	args["VVL"] = "(const NameExpr* n1, const NameExpr* n2, const ListExpr* l)"
	args["ViHL"] = "(const NameExpr* n, int i, EventHandler* h, const ListExpr* l)"
	args["CiHL"] = "(const ConstExpr* c, int i, EventHandler* h, const ListExpr* l)"

	args2["X"] = ""
	args2["O"] = "reg"
	args2["R"] = "n1, n2, f->Field()"
	args2["Ri"] = "n1, n2, field"
	args2["V"] = "n"
	args2["VV"] = "n1, n2"
	args2["VO"] = "n, reg"
	args2["VVV"] = "n1, n2, n3"
	args2["VLV"] = "n1, l, n2"
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
	exprV["VVVV"] = "lhs, r1->AsNameExpr(), r2->AsNameExpr(), r3->AsNameExpr()"

	accessors["I"] = ".int_val"
	accessors["U"] = ".uint_val"
	accessors["D"] = ".double_val"

	accessors["A"] = ".addr_val"
	accessors["N"] = ".subnet_val"
	accessors["P"] = ".re_val"
	accessors["S"] = ".string_val"
	accessors["T"] = ".table_val"
	accessors["X"] = "###"

	# Update eval(...) below

	eval_selector["I"] = ""
	eval_selector["U"] = ""
	eval_selector["D"] = ""
	eval_selector["A"] = "A"
	eval_selector["N"] = "N"
	eval_selector["P"] = "P"
	eval_selector["S"] = "S"
	eval_selector["T"] = "T"

	++no_vec["P"]
	++no_vec["T"]

	method_map["I"] = "i_t == TYPE_INTERNAL_INT"
	method_map["U"] = "i_t == TYPE_INTERNAL_UNSIGNED"
	method_map["D"] = "i_t == TYPE_INTERNAL_DOUBLE"
	method_map["A"] = "i_t == TYPE_INTERNAL_ADDR"
	method_map["N"] = "i_t == TYPE_INTERNAL_SUBNET"
	method_map["P"] = "tag == TYPE_PATTERN"
	method_map["S"] = "i_t == TYPE_INTERNAL_STRING"
	method_map["T"] = "tag == TYPE_TABLE"

	# Suffix used for vector operations.
	vec = "_vec"
	}

$1 == "op"	{ dump_op(); op = $2; next }
$1 == "expr-op"	{ dump_op(); op = $2; expr_op = 1; next }
$1 == "unary-op"	{ dump_op(); op = $2; ary_op = 1; next }
$1 == "direct-unary-op" {
	dump_op(); op = $2; direct_method = $3; direct_op = 1; next
	}
$1 == "unary-expr-op"	{ dump_op(); op = $2; expr_op = 1; ary_op = 1; next }
$1 == "binary-expr-op"	{ dump_op(); op = $2; expr_op = 1; ary_op = 2; next }
$1 == "rel-expr-op"	{
	dump_op(); op = $2; expr_op = 1; ary_op = 2; rel_op = 1; next
	}
$1 == "internal-op"	{ dump_op(); op = $2; internal_op = 1; next }
$1 == "internal-binary-op" {
	dump_op(); op = $2; binary_op = internal_op = 1; next
	}

$1 == "op-accessor"	{ op1_accessor = op2_accessor = $2; next }
$1 == "op1-accessor"	{ op1_accessor = $2; next }
$1 == "op2-accessor"	{ op2_accessor = $2; next }

$1 == "type"	{ type = $2; next }
$1 == "vector"	{ vector = 1; next }
$1 ~ /^op-type(s?)$/	{ build_op_types(); next }
$1 == "opaque"	{ opaque = 1; next }

$1 == "set-type"	{ set_type = $2; next }
$1 == "set-expr"	{ set_expr = $2; next }

$1 ~ /^eval((_[ANPST])?)$/	{
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
		if ( ! operand_type || eval_sub || binary_op )
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
		mix_eval = all_but_first_n(3)
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
		if ( $i in accessors )
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
					ex = expand_eval(esel, expr_op,
								i, i, j, 0)
					}

				build_op(op, "V" op1, i, i, esel, ex, j, 0)
				}

			continue;
			}

		# Loop over constant, var for second operand
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
		ex = expand_eval(eval[sel], expr_op, i, i, j, k)
		build_op(op, "V" op1 op2, i, i, eval[sel], ex, j, k)
		}

	if ( mix_eval )
		{
		ex = expand_eval(mix_eval, expr_op, ev_mix1, ev_mix2, j, k)
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
			      (j ? "frame[s.v2]" : "s.c") \
			      "." op1_accessor ";\n\t\t")

			a2 = ("auto op2 = " \
			      (k ? "frame[s." op3 "]": "s.c") \
			      "." op2_accessor ";\n\t\t")

			assign = "frame[s.v1]" accessors[op_type_rep]

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

function expand_eval(e, is_expr_op, otype1, otype2, is_var1, is_var2)
	{
	laccessor = raccessor1 = raccessor2 = ""
	expr_app = ""
	if ( otype1 )
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
	pre_copy = eval_pre
	rep1 = "(" (is_var1 ? "frame[s.v2]" : "s.c") raccessor1 ")"
	gsub(/\$1/, rep1, e_copy)
	gsub(/\$1/, rep1, pre_copy)

	if ( ary_op == 2 )
		{
		# If one of the operands is a constant, then we use
		# v2 and not v3 to hold the other (non-constant) operand.
		op3 = (is_var1 && is_var2) ? "v3" : "v2"
		rep2 = "(" (is_var2 ? "frame[s." op3 "]" : "s.c") raccessor2 ")"
		gsub(/\$2/, rep2, e_copy)
		gsub(/\$2/, rep2, pre_copy)
		}

	if ( is_expr_op )
		{
		if ( index(e_copy, "$$") > 0 )
			{
			gsub(/\$\$/, "frame[s.v1]" laccessor, e_copy)
			return pre_copy e_copy expr_app
			}
		else
			return pre_copy \
				"frame[s.v1]" laccessor " = " e_copy expr_app
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
	if ( sub_type1 && sub_type1 != "X" )
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
	do_vec = vector && ! no_vec[sub_type1]

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
		}

	print ("\t" full_op ",") >ops_f
	if ( do_vec )
		print ("\t" full_op vec ",") >ops_f

	print ("\tcase " full_op ":\treturn \"" tolower(orig_op) \
		"-" type orig_suffix "\";") >ops_names_f
	if ( do_vec )
		print ("\tcase " full_op vec ":\treturn \"" tolower(orig_op) \
			"-" type orig_suffix "-vec" "\";") >ops_names_f

	if ( no_eval )
		print ("\tcase " full_op ":\tbreak;") >ops_eval_f
	else
		print ("\tcase " full_op ":\n\t\t{ " \
			multi_eval eval multi_eval eval_blank \
			"}" multi_eval eval_blank "break;\n") >ops_eval_f

	if ( do_vec && ! no_eval )
		{
		if ( ary_op == 1 )
			{
			print ("\tcase " full_op vec ":\n\t\tvec_exec(" full_op vec \
				", frame[s.v1].raw_vector_val,\n\t\t\t" \
				(is_var1 ? "frame[s.v2]" : "s.c") \
				".raw_vector_val);\n\t\tbreak;\n") >ops_eval_f

			oe_copy = orig_eval
			gsub(/\$1/, "(*v2)[i]" raccessor1, oe_copy)

			print ("\tcase " full_op vec ": (*v1)[i]" laccessor " = " \
				oe_copy "; break;") >vec1_eval_f
			}

		else
			{
			### Right now we wind up generating 3 identical
			### case bodies for VCV, VVC, and VVV.  This gives
			### us some latitude in case down the line we
			### come up with a different vector scheme that
			### varies for constant vectors, but we could
			### consider compressing them down in the interest
			### of smaller code size.

			# See comment above for the role of op3.
			op3 = (is_var1 && is_var2) ? "v3" : "v2"

			print ("\tcase " full_op vec ":\n\t\tvec_exec("  \
				full_op vec \
				",\n\t\t\tframe[s.v1].raw_vector_val,\n\t\t\t" \
				(is_var1 ? "frame[s.v2]" : "s.c") \
				".raw_vector_val, " \
				(is_var2 ? "frame[s." op3 "]" : "s.c") \
				".raw_vector_val);\n\t\tbreak;\n") >ops_eval_f

			oe_copy = orig_eval
			gsub(/\$1/, "(*v2)[i]" raccessor1, oe_copy)
			gsub(/\$2/, "(*" op3 ")[i]" raccessor2, oe_copy)

			# Check for whether "$$" is meaningful, which
			# occurs for types with non-atomic frame values,
			# and also for any mixed evaluation.
			if ( eval_selector[sub_type1] != "" ||
			     sub_type1 != sub_type2 )
				{
				### Need to resolve whether to "delete"
				### here.
				gsub(/\$\$/, "(*v1)[i]" laccessor, oe_copy)
				print ("\tcase " full_op vec ":\n\t\t{\n\t\t" \
					oe_copy "\n\t\tbreak;\n\t\t}") >vec2_eval_f
				}

			else
				print ("\tcase " full_op vec ":\n\t\t(*v1)[i]" \
					laccessor " = " \
					oe_copy "; break;") >vec2_eval_f
			}
		}

	if ( ! internal_op && is_rep )
		{
		gen_method(full_op_no_sub, full_op, type, sub_type1,
				0, method_pre)

		if ( do_vec )
			gen_method(full_op_no_sub, full_op, type, sub_type1,
					1, method_pre)
		}

	if ( type == "R" )
		{
		print ("\tcase EXPR_" upper_op ":\treturn c->" op_type \
			"(lhs, r1->AsNameExpr(), rhs->AsFieldExpr());") >exprsV_f
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
		}
	}

function gen_method(full_op_no_sub, full_op, type, sub_type, is_vec, method_pre)
	{
	print ("const CompiledStmt AbstractMachine::" \
		(op_type (is_vec ? vec : "")) args[type]) >methods_f

	print ("\t{") >methods_f

	if ( custom_method )
		{
		cm_copy = custom_method
		gsub(/\$\*/, args2[type], cm_copy)
		print ("\t" cm_copy) >methods_f
		# This { balances the following one so searches for matching
		# braces are not thrown off.
		print ("\t}\n") >methods_f
		return
		}

	if ( method_pre )
		print ("\t" method_pre ";") >methods_f

	if ( type == "O" || type == "VO" )
		{
		pre_arg = type == "O" ? "" : ", FrameSlot(n)"
		print ("\treturn AddStmt(AbstractStmt(" \
			full_op pre_arg ", reg));") >methods_f
		}

	else if ( type == "R" )
		{
		print ("\tauto s = GenStmt(this, " full_op ", " \
			args2[type] ");") >methods_f
		print ("\ts.t = n1->Type().get();") >methods_f
		print ("\treturn AddStmt(s);") >methods_f
		}

	else if ( args2[type] != "" )
		{
		# This is the only scenario where sub_type should occur.
		part1 = "\tauto s = GenStmt(this, "

		part2a = ", " args2[type] ");\n"
		part2c = "\treturn AddStmt(s);"

		if ( sub_type && sub_type != "X" )
			{
			# The code will be indented due to if-else constructs.
			part1 = "\t" part1
			part2a = part2a
			part2c = "\t" part2c
			}

		# Provide access to the individual variables.
		split(args2[type], vars, /, /)

		if ( set_type )
			{
			# Remove extraneous $, if present.
			sub(/\$/, "", set_type)

			part2b = "\ts.t = " vars[set_type] "->Type().get();\n"

			if ( sub_type )
				part2b = "\t" part2b
			}
		else
			part2b = ""

		if ( set_expr )
			{
			# Remove extraneous $, if present.
			sub(/\$/, "", set_expr)

			part2b = part2b "\ts.e = " vars[set_expr] ";\n"

			if ( sub_type )
				part2b = "\t" part2b
			}

		part2 = part2a part2b part2c

		if ( sub_type && sub_type != "X" )
			{
			# Need braces for multi-line parts.
			part1 = "\t\t{\n" part1
			part2 = part2 "\n\t\t}"

			# Figure out the type to use to select which
			# flavor of the operation to generate.  For
			# operations with three operands, select the
			# second operand, not the first, in order to
			# generate correct typing for relationals (where
			# the first operand has a type of bool regardless
			# of the types of the other operands).
			op1_is_const = type ~ /^VC/
			op2_is_const = type ~ /^V.C/

			op2_param = op2_is_const ? "c" : "n2"

			if ( type ~ /^.../ )
				# Has three operands, choose second.
				test_var = op2_param
			else
				test_var = op1_is_const ? "c" : "n1"

			print ("\tauto t = " test_var "->Type();") >methods_f
			print ("\tauto tag = t->Tag();") >methods_f
			print ("\tauto i_t = t->InternalType();") >methods_f

			n = 0;
			for ( o in op_types )
				{
				if ( is_vec && no_vec[o] )
					continue

				invoke1 = (part1 full_op_no_sub "_")
				invoke2 = ((is_vec ? vec : "") part2)

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
				if ( ev_mix1 != "P" || ev_mix2 != "S" )
					gripe("unsupported eval-mixed")

				print ("\t" else_text "if ( tag == TYPE_PATTERN && " op2_param "->Type()->Tag() == TYPE_STRING )") >methods_f
				print ("\t" part1 (full_op_no_sub "_PS") \
					part2) >methods_f
				}

			print ("\telse\n\t\treporter->InternalError(\"bad internal type\");") >methods_f
			}
		else
			print (part1 full_op part2) >methods_f
		}
	else
		print ("\treturn AddStmt(GenStmt(this, \
			" full_op "));") >methods_f

	print ("\t}\n") >methods_f
	}

function build_method_conditional(o, n)
	{
	else_text = (n > 1) ? "else " : "";
	test = method_map[o]
	print ("\t" else_text "if ( " test " )") >methods_f
	}

function clear_vars()
	{
	opaque = set_expr = set_type = type = operand_type = ""
	custom_method = method_pre = eval_pre = ""
	no_eval = mix_eval = multi_eval = eval_blank = ""
	vector = binary_op = internal_op = rel_op = ary_op = expr_op = op = ""
	direct_method = direct_op = ""
	laccessor = raccessor1 = raccessor2 = ""
	op1_accessor = op2_accessor = ""

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
