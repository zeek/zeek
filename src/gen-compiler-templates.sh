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
	}

$1 == "op"	{ dump_op(); op = $2; expr_op = 0; next }
$1 == "expr-op"	{ dump_op(); op = $2; expr_op = 1; next }

$1 == "type"	{ type = $2; next }
$1 == "opaque"	{ opaque = 1; next }
$1 == "eval"	{ eval = all_but_first(); next }

$1 == "method-pre"	{ method_pre = all_but_first(); next }

/^#/		{ next }
/^[ \t]*$/	{ next }

	{
	print "unrecognized compiler template line:", $0
	exit(1)
	}

END	{
	dump_op()

	finish(exprsC1_f, "C1")
	finish(exprsC2_f, "C2")
	finish(exprsC3_f, "C3")
	finish(exprsV_f, "V")
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
	if ( op == "" )
		return

	if ( ! (type in args) )
		{
		print "bad type " type " for " op
		exit(1)
		}

	upper_op = toupper(op)
	full_op = "OP_" upper_op "_" type
	op_type = op type

	print ("\tvirtual const CompiledStmt " op_type args[type] " = 0;") >base_class_f
	print ("\tconst CompiledStmt " op_type args[type] " override;") >sub_class_f
	print ("\t" full_op ",") >ops_f
	print ("\tcase " full_op ":\treturn \"" op "_" type "\";") >ops_names_f
	print ("\tcase " full_op ":\t" eval "; break;") >ops_eval_f

	print ("const CompiledStmt AbstractMachine::" op_type args[type]) >methods_f

	print ("\t{") >methods_f
	if ( method_pre )
		print ("\t" method_pre ";") >methods_f
	if ( type == "O" )
		print ("\treturn AddStmt(AbstractStmt(" full_op ", reg));") >methods_f
	else if ( args2[type] != "" )
		print ("\treturn AddStmt(GenStmt(this, " full_op ", " args2[type] "));") >methods_f
	else
		print ("\treturn AddStmt(GenStmt(this, " full_op"));") >methods_f

	print ("\t}\n") >methods_f

	if ( expr_op )
		{
		if ( type == "C" )
			{
			print "bad type " type " for expr " op
			exit(1)
			}

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
			{
			print "bad type " type " for expr " op
			exit(1)
			}

		print ("\tcase " expr_case ":\treturn c->" op_type "(" eargs ");") >f
		}

	opaque = op = type = eval = method_pre = ""
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

' $*
