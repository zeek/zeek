#! /bin/sh

awk '
BEGIN	{
	base_class_f = "CompilerBaseDefs.h"
	sub_class_f = "CompilerSubDefs.h"
	ops_f = "CompilerOpsDefs.h"
	ops_names_f = "CompilerOpsNamesDefs.h"
	ops_eval_f = "CompilerOpsEvalDefs.h"
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
	args["V"] = "(const NameExpr* n)"
	args["VV"] = "(const NameExpr* n1, const NameExpr* n2)"
	args["VVV"] = "(const NameExpr* n1, const NameExpr* n2, const NameExpr* n3)"
	args["VVVV"] = "(const NameExpr* n1, const NameExpr* n2, const NameExpr* n3, const NameExpr* n4)"
	args["C"] = "(const ConstExpr* c)"
	args["VC"] = "(const NameExpr* n, ConstExpr* c)"
	args["VVC"] = "(const NameExpr* n1, const NameExpr* n2, ConstExpr* c)"
	args["VCV"] = "(const NameExpr* n1, ConstExpr* c, const NameExpr* n2)"

	args2["X"] = ""
	args2["O"] = "reg"
	args2["V"] = "n"
	args2["VV"] = "n1, n2"
	args2["VVV"] = "n1, n2, n3"
	args2["VVVV"] = "n1, n2, n3, n4"
	args2["C"] = "c"
	args2["VC"] = "n, c"
	args2["VVC"] = "n1, n2, c"
	args2["VCV"] = "n1, c, n2"

	exprC1["VC"] = "lhs, r1->AsConstExpr()";
	exprC1["VCV"] = "lhs, r1->AsConstExpr(), r2->AsNameExpr()"

	exprC2["VVC"] = "lhs, r1->AsNameExpr(), r2->AsConstExpr()"
	exprC2["VVCC"] = "lhs, r1->AsNameExpr(), r2->AsConstExpr(), r3->AsConstExpr()"
	exprC2["VVCV"] = "lhs, r1->AsNameExpr(), r2->AsConstExpr(), r3->AsNameExpr()"

	exprC3["VVVC"] = "lhs, r1->AsNameExpr(), r2->AsNameExpr(), r3->AsConstExpr()"

	exprV["X"] = ""
	exprV["V"] = "lhs"
	exprV["VV"] = "lhs, r1->AsNameExpr()"
	exprV["VVV"] = "lhs, r1->AsNameExpr(), r2->AsNameExpr()"
	exprV["VVVV"] = "lhs, r1->AsNameExpr(), r2->AsNameExpr(), r3->AsNameExpr()"

	accessors["I"] = ".int_val"
	accessors["U"] = ".uint_val"
	accessors["D"] = ".double_val"

	# Suffix used for vector operations.
	vec = "_vec"
	}

$1 == "op"	{ dump_op(); op = $2; next }
$1 == "expr-op"	{ dump_op(); op = $2; expr_op = 1; next }
$1 == "unary-op"	{ dump_op(); op = $2; unary_op = 1; next }
$1 == "unary-expr-op"	{ dump_op(); op = $2; expr_op = 1; unary_op = 1; next }
$1 == "internal-op"	{ dump_op(); op = $2; internal_op = 1; next }

$1 == "type"	{ type = $2; next }
$1 == "vector"	{ vector = 1; next }
$1 ~ /^op-type(s?)$/	{ build_op_types(); next }
$1 == "opaque"	{ opaque = 1; next }
$1 == "eval"	{
		new_eval = all_but_first()
		if ( operand_type == "" )
			new_eval = new_eval ";"

		if ( eval )
			{
			if ( operand_type )
				gripe("cannot intermingle op-type and multi-line evals")

			eval = eval "\n\t\t" new_eval

			# The following variables are just to enable
			# us to produce tidy-looking switch blocks.
			multi_eval = "\n\t\t"
			eval_blank = ""
			}
		else
			{
			eval = new_eval
			eval_blank = " "
			}
		next
		}

$1 == "method-pre"	{ method_pre = all_but_first(); next }

/^#/		{ next }
/^[ \t]*$/	{ next }

	{ gripe("unrecognized compiler template line: " $0) }

END	{
	dump_op()

	finish(exprsC1_f, "C1")
	finish(exprsC2_f, "C2")
	finish(exprsC3_f, "C3")
	finish(exprsV_f, "V")
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
	all = ""
	for ( i = 2; i <= NF; ++i )
		{
		if ( i > 2 )
			all = all " "

		all = all $i
		}

	return all
	}

function dump_op()
	{
	if ( ! op )
		return

	if ( unary_op )
		{
		# Note, for most operators the constant version would have
		# already been folded, but for some like AppendTo, they
		# cannot, so we account for that possibility here.

		if ( operand_type )
			{
			for ( i in op_types )
				{
				build_op(op, "VV", i,
					expand_eval(eval, expr_op, i, 1))
				build_op(op, "VC", i,
					expand_eval(eval, expr_op, i, 0))
				}
			}

		else
			{
			build_op(op, "VV", "", expand_eval(eval, expr_op, 0, 1))
			build_op(op, "VC", "", expand_eval(eval, expr_op, 0, 0))
			}
		}
	else
		build_op(op, type, "", eval)

	clear_vars()
	}

function expand_eval(e, is_expr_op, otype, is_var)
	{
	accessor = ""
	expr_app = ""
	if ( otype )
		{
		if ( ! (otype in accessors) )
			gripe("bad operand_type: " otype)

		accessor = accessors[otype]
		expr_app = ";"
		}

	rep = "(" (is_var ? "frame[s.v2]" : "s.c") accessor ")"
	e_copy = e
	gsub(/\$1/, rep, e_copy)

	if ( is_expr_op )
		return "frame[s.v1]" accessor " = " e_copy expr_app
	else
		return e_copy accessor
	}

function build_op(op, type, sub_type, eval)
	{
	if ( ! (type in args) )
		gripe("bad type " type " for " op)

	orig_op = op
	gsub(/-/, "_", op)
	upper_op = toupper(op)
	op_type = op type

	full_op = "OP_" upper_op "_" type
	full_op_no_sub = full_op
	if ( sub_type )
		full_op = full_op "_" sub_type

	# Track whether this is the "representative" operand for
	# operations with multiple types of operands.  This lets us
	# avoid redundant declarations.
	is_rep = ! sub_type || sub_type == op_type_rep

	if ( ! internal_op && is_rep )
		{
		print ("\tvirtual const CompiledStmt " \
			op_type args[type] " = 0;") >base_class_f
		print ("\tconst CompiledStmt " op_type args[type] \
			" override;") >sub_class_f

		if ( vector )
			{
			print ("\tvirtual const CompiledStmt " \
				op_type vec args[type] " = 0;") >base_class_f
			print ("\tconst CompiledStmt " op_type vec \
				args[type] " override;") >sub_class_f
			}
		}

	print ("\t" full_op ",") >ops_f
	if ( vector )
		print ("\t" full_op vec ",") >ops_f

	print ("\tcase " full_op ":\treturn \"" tolower(orig_op) \
		"-" type "\";") >ops_names_f
	if ( vector )
		print ("\tcase " full_op vec ":\treturn \"" tolower(orig_op) \
			"-" type "-vec" "\";") >ops_names_f

	print ("\tcase " full_op ":\n\t\t{ " \
		multi_eval eval multi_eval eval_blank \
		"}" multi_eval eval_blank "break;\n") >ops_eval_f
	if ( vector )
		print ("\tcase " full_op vec ":\n\t\t{ " \
			multi_eval eval multi_eval eval_blank \
			"}" multi_eval eval_blank "break;\n") >ops_eval_f

	if ( ! internal_op && is_rep )
		gen_method(full_op_no_sub, full_op, type, sub_type, method_pre)

	if ( expr_op && is_rep )
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

		print ("\tcase " expr_case ":\treturn c->" op_type "(" eargs ");") >f
		}
	}

function gen_method(full_op_no_sub, full_op, type, sub_type, method_pre)
	{
	print ("const CompiledStmt AbstractMachine::" op_type args[type]) >methods_f

	print ("\t{") >methods_f
	if ( method_pre )
		print ("\t" method_pre ";") >methods_f
	if ( type == "O" )
		print ("\treturn AddStmt(AbstractStmt(" full_op ", reg));") >methods_f
	else if ( args2[type] != "" )
		{
		# This is the only scenario where sub_type should occur.
		part1 = "\treturn AddStmt(GenStmt(this, "
		part2 = ", " args2[type] "));"

		if ( sub_type )
			{
			# Only works for unary.
			op1_is_const = type ~ /^VC/
			test_var = op1_is_const ? "c" : "n2"
			print ("\tauto t = " test_var "->Type()->InternalType();") >methods_f

			n = 0;
			for ( i in op_types )
				{
				else_text = ((++n > 1) ? "else " : "");
				if ( i == "I" || i == "U" )
					{
					print ("\t" else_text "if ( t == TYPE_INTERNAL_INT || t == TYPE_INTERNAL_UNSIGNED )") >methods_f
					}
				else if ( i == "D" )
					print ("\t" else_text "if ( t == TYPE_INTERNAL_DOUBLE )") >methods_f
				else
					gripe("bad subtype " i)

				print ("\t" part1 (full_op_no_sub "_" i) part2) >methods_f
				}

			print ("\telse\n\t\treporter->InternalError(\"bad internal type\");") >methods_f
			}
		else
			print (part1 full_op part2) >methods_f
		}
	else
		print ("\treturn AddStmt(GenStmt(this, " full_op "));") >methods_f

	print ("\t}\n") >methods_f
	}

function clear_vars()
	{
	opaque = type = eval = multi_eval = eval_blank = method_pre = ""
	vector = internal_op = unary_op = expr_op = op = ""
	operand_type = ""
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
	print ("\t\treporter->InternalError(\"inconsistency in " which " AssignExpr::Compile\");") >f
	print ("\t}\t}") >f
	}

function gripe(msg)
	{
	print "error at input line", NR ":", msg
	exit(1)
	}
' $*
