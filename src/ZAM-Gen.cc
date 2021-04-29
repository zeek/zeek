// See the file "COPYING" in the main distribution directory for copyright.

#include <ctype.h>
#include <regex>

#include "ZAM-Gen.h"

using namespace std;

char dash_to_under(char c)
	{
	if ( c == '-' )
		return '_';
	return c;
	}

char under_to_dash(char c)
	{
	if ( c == '_' )
		return '-';
	return c;
	}


struct TypeInfo {
	string tag;
	ZAM_ExprType et;
	string suffix;
	string accessor;	// doesn't include "_val"
	bool is_managed;
};

static vector<TypeInfo> ZAM_type_info = {
	{ "TYPE_ADDR",		ZAM_EXPR_TYPE_ADDR,	"A", "addr", true },
	{ "TYPE_ANY",		ZAM_EXPR_TYPE_ANY,	"", "any", true },
	{ "TYPE_COUNT",		ZAM_EXPR_TYPE_UINT,	"U", "uint", false },
	{ "TYPE_DOUBLE",	ZAM_EXPR_TYPE_DOUBLE,	"D", "double", false },
	{ "TYPE_INT",		ZAM_EXPR_TYPE_INT,	"I", "int", false },
	{ "TYPE_PATTERN",	ZAM_EXPR_TYPE_PATTERN,	"P", "re", true },
	{ "TYPE_STRING",	ZAM_EXPR_TYPE_STRING,	"S", "string", true },
	{ "TYPE_SUBNET",	ZAM_EXPR_TYPE_SUBNET,	"N", "subnet", true },
	{ "TYPE_TABLE",		ZAM_EXPR_TYPE_TABLE,	"T", "table", true },
	{ "TYPE_VECTOR",	ZAM_EXPR_TYPE_VECTOR,	"V", "vector", true },

	{ "TYPE_FILE",		ZAM_EXPR_TYPE_NONE, "f", "file", true },
	{ "TYPE_FUNC",		ZAM_EXPR_TYPE_NONE, "F", "func", true },
	{ "TYPE_LIST",		ZAM_EXPR_TYPE_NONE, "L", "list", true },
	{ "TYPE_OPAQUE",	ZAM_EXPR_TYPE_NONE, "O", "opaque", true },
	{ "TYPE_RECORD",	ZAM_EXPR_TYPE_NONE, "R", "record", true },
	{ "TYPE_TYPE",		ZAM_EXPR_TYPE_NONE, "t", "type", true },
};

const TypeInfo& find_type_info(ZAM_ExprType et)
	{
	assert(et != ZAM_EXPR_TYPE_NONE);

	for ( auto& ti : ZAM_type_info )
		if ( ti.et == et )
			return ti;

	assert(false);
	return ZAM_type_info[0];
	}


unordered_map<ZAM_OperandType, pair<const char*, const char*>>
 ArgsManager::ot_to_args = {
	{ ZAM_OT_AUX, { "OpaqueVals*", "v" } },
	{ ZAM_OT_CONSTANT, { "const ConstExpr*", "c" } },
	{ ZAM_OT_EVENT_HANDLER, { "EventHandler*", "h" } },
	{ ZAM_OT_INT, { "int", "i" } },
	{ ZAM_OT_LIST, { "const ListExpr*", "l" } },
	{ ZAM_OT_RECORD_FIELD, { "const NameExpr*", "n" } },
	{ ZAM_OT_VAR, { "const NameExpr*", "n" } },

	// The following gets special treatment.
	{ ZAM_OT_FIELD, { "const NameExpr*", "n" } },
};

ArgsManager::ArgsManager(const vector<ZAM_OperandType>& ot, bool is_cond)
	{
	int n = 0;
	bool add_field = false;

	for ( auto ot_i : ot )
		{
		if ( ot_i == ZAM_OT_NONE )
			{
			assert(ot.size() == 1);
			break;
			}

		if ( n++ == 0 && is_cond )
			// Skip the conditional's nominal assignment slot.
			continue;

		// Start off the argument info using the usual case
		// of (1) same method parameter name as GenInst argument,
		// and (2) not requiring a record field.
		auto& arg_i = ot_to_args[ot_i];
		Arg arg = { arg_i.second, arg_i.first, arg_i.second, false };

		if ( ot_i == ZAM_OT_FIELD )
			{
			arg.is_field = true;

			if ( n == 1 )
				{
				arg.decl_name = "flhs";
				arg.decl_type = "const FieldLHSAssignExpr*";
				}
			}

		args.emplace_back(move(arg));
		}

	Differentiate();
	}

void ArgsManager::Differentiate()
	{
	// First, figure out which parameter names are used how often.
	map<string, int> name_count;	// how often the name apepars
	map<string, int> usage_count;	// how often the name's been used so far
	for ( auto& arg : args )
		{
		auto& name = arg.param_name;
		if ( name_count.count(name) == 0 )
			{
			name_count[name] = 1;
			usage_count[name] = 0;
			}
		else
			++name_count[name];
		}

	// Now for each name - whether appearing as an argument or in
	// a declaration - if it's used more than once, then differentiate
	// it.  Note, some names only appear multiple times as arguments,
	// but not in the declarations.
	for ( auto& arg : args )
		{
		auto& decl = arg.decl_name;
		auto& name = arg.param_name;
		bool decl_and_arg_same = decl == name;

		if ( name_count[name] == 1 )
			continue;

		auto n = to_string(++usage_count[name]);
		name += n;
		if ( decl_and_arg_same )
			decl += n;
		}

	// Finally, build the full versions of the declaration and
	// parameters.
	int num_fields = 0;
	for ( auto& arg : args )
		{
		if ( full_decl.size() > 0 )
			full_decl += ", ";

		full_decl += arg.decl_type + " " + arg.decl_name;

		if ( full_params.size() > 0 )
			full_params += ", ";

		full_params += arg.param_name;
		params.push_back(arg.param_name);

		if ( arg.is_field )
			++num_fields;
		}

	assert(num_fields <= 2);

	if ( num_fields == 1 )
		full_params += ", field";
	else if ( num_fields == 2 )
		{
		full_decl += ", int field2";
		full_params += ", field1, field2";
		}
	}


ZAM_OpTemplate::ZAM_OpTemplate(ZAMGen* _g, string _base_name)
: g(_g), base_name(move(_base_name))
	{
	orig_name = base_name;
	transform(base_name.begin(), base_name.end(), base_name.begin(),
	          dash_to_under);

	cname = base_name;
	transform(cname.begin(), cname.end(), cname.begin(), ::toupper);
	}

void ZAM_OpTemplate::Build()
	{
	op_loc = g->CurrLoc();

	string line;
	while ( g->ScanLine(line) )
		{
		if ( line.size() <= 1 )
			break;

		auto words = g->SplitIntoWords(line);
		if ( words.size() == 0 )
			break;

		Parse(words[0], line, words);
		}
	}

void ZAM_OpTemplate::Instantiate()
	{
	InstantiateOp(OperandTypes(), IncludesVectorOp());
	}

void ZAM_OpTemplate::UnaryInstantiate()
	{
	// First operand is always the frame slot to which this operation
	// assigns the result of the applying unary operator.
	vector<ZAM_OperandType> ots = { ZAM_OT_VAR };
	ots.resize(2);

	// Now build versions for a constant operand (maybe not actually
	// needed due to constant folding, but sometimes that gets deferred
	// to run-time) ...
	if ( ! NoConst() )
		{
		ots[1] = ZAM_OT_CONSTANT;
		InstantiateOp(ots, IncludesVectorOp());
		}

	// ... and for a variable (frame-slot) operand.
	ots[1] = ZAM_OT_VAR;
	InstantiateOp(ots, IncludesVectorOp());
	}

void ZAM_OpTemplate::Parse(const string& attr, const string& line, const Words& words)
	{
	int num_args = -1;	// -1 = don't enforce
	int nwords = words.size();

	if ( attr == "type" )
		{
		num_args = 1;
		if ( nwords > 1 )
			{
			const char* types = words[1].c_str();
			while ( *types )
				{
				ZAM_OperandType ot = ZAM_OT_NONE;
				switch ( *types ) {
				case 'C':	ot = ZAM_OT_CONSTANT; break;
				case 'F':	ot = ZAM_OT_FIELD; break;
				case 'H':	ot = ZAM_OT_EVENT_HANDLER; break;
				case 'L':	ot = ZAM_OT_LIST; break;
				case 'O':	ot = ZAM_OT_AUX; break;
				case 'R':	ot = ZAM_OT_RECORD_FIELD; break;
				case 'V':	ot = ZAM_OT_VAR; break;
				case 'i':	ot = ZAM_OT_INT; break;

				case 'X':	ot = ZAM_OT_NONE; break;

				default:
					g->Gripe("bad operand type", words[1]);
					break;
				}

				AddOpType(ot);

				++types;
				}
			}
		}

	else if ( attr == "op1-read" )
		{
		num_args = 0;
		SetOp1Flavor("OP1_READ");
		}

	else if ( attr == "op1-read-write" )
		{
		num_args = 0;
		SetOp1Flavor("OP1_READ_WRITE");
		}

	else if ( attr == "op1-internal" )
		{
		num_args = 0;
		SetOp1Flavor("OP1_INTERNAL");
		}

	else if ( attr == "set-type" )
		{
		num_args = 1;
		if ( nwords > 1 )
			SetTypeParam(ExtractTypeParam(words[1]));
		}

	else if ( attr == "set-type2" )
		{
		num_args = 1;
		if ( nwords > 1 )
			SetType2Param(ExtractTypeParam(words[1]));
		}

	else if ( attr == "custom-method" )
		SetCustomMethod(g->SkipWords(line, 1));

	else if ( attr == "method-post" )
		SetPostMethod(g->SkipWords(line, 1));

	else if ( attr == "side-effects" )
		{
		if ( nwords == 3 )
			SetAssignmentLess(words[1], words[2]);
		else
			// otherwise shouldn't be any arguments
			num_args = 0;

		SetHasSideEffects();
		}

	else if ( attr == "no-eval" )
		{
		num_args = 0;
		SetNoEval();
		}

	else if ( attr == "vector" )
		{
		num_args = 0;
		SetIncludesVectorOp();
		}

	else if ( attr == "assign-val" )
		{
		num_args = 1;
		if ( words.size() > 1 )
			SetAssignVal(words[1]);
		}

	else if ( attr == "eval" )
		{
		AddEval(g->SkipWords(line, 1));

		auto addl = GatherEval();
		if ( addl.size() > 0 )
			AddEval(addl);
		}

	else
		g->Gripe("unknown template attribute", attr);

	if ( num_args >= 0 && num_args != nwords - 1 )
		g->Gripe("extraneous arguments", line);
	}

string ZAM_OpTemplate::GatherEval()
	{
	string res;
	string l;
	while ( g->ScanLine(l) )
		{
		if ( l.size() <= 1 || ! isspace(l.c_str()[0]) )
			{
			g->PutBack(l);
			return res;
			}

		res += l;
		}

	return res;
	}

int ZAM_OpTemplate::ExtractTypeParam(const string& arg)
	{
	auto param_str = arg.c_str();
	if ( *param_str != '$' )
		g->Gripe("bad set-type parameter, should be $n", arg);

	int param = atoi(&param_str[1]);

	if ( param <= 0 || param > 3 )
		g->Gripe("bad set-type parameter, should be $1/$2/$3", arg);

	return param;
	}

unordered_map<ZAM_OperandType, char> ZAM_OpTemplate::ot_to_char = {
	{ ZAM_OT_AUX, 'O' },
	{ ZAM_OT_CONSTANT, 'C' },
	{ ZAM_OT_EVENT_HANDLER, 'H' },
	{ ZAM_OT_FIELD, 'F' },
	{ ZAM_OT_INT, 'i' },
	{ ZAM_OT_LIST, 'L' },
	{ ZAM_OT_NONE, 'X' },
	{ ZAM_OT_RECORD_FIELD, 'R' },
	{ ZAM_OT_VAR, 'V' },
};

void ZAM_OpTemplate::InstantiateOp(const vector<ZAM_OperandType>& ot, bool do_vec)
	{
	auto method = MethodName(ot);

	InstantiateOp(method, ot, false, false, false);

	if ( IncludesFieldOp() )
		InstantiateOp(method, ot, true, false, false);

	if ( do_vec )
		InstantiateOp(method, ot, false, true, false);

	if ( IsConditional() )
		InstantiateOp(method, ot, false, false, true);
	}

void ZAM_OpTemplate::InstantiateOp(const string& method,
                                   const vector<ZAM_OperandType>& ot,
                                   bool is_field, bool is_vec, bool is_cond)
	{
	string suffix = "";

	if ( is_field )	suffix = "_field";
	if ( is_vec )	suffix = "_vec";
	if ( is_cond )	suffix = "_cond";

	if ( ! IsInternalOp() )
		InstantiateMethod(method, suffix, ot, is_field, is_vec, is_cond);

	if ( IsAssignOp() )
		InstantiateAssignOp(ot, suffix);
	else
		InstantiateEval(ot, suffix, is_field, is_vec, is_cond);
	}

void ZAM_OpTemplate::InstantiateMethod(const string& m, const string& suffix,
                                       const vector<ZAM_OperandType>& ot,
                                       bool is_field, bool is_vec, bool is_cond)
	{
	if ( IsInternalOp() )
		return;

	auto decls = MethodDecl(ot, is_field, is_cond);

	EmitTo(BaseDecl);
	Emit("virtual const CompiledStmt " + m + suffix + "(" + decls +
	     ") = 0;");

	EmitTo(SubDecl);
	Emit("const CompiledStmt " + m + suffix + "(" + decls + ") override;");

	EmitTo(MethodDef);
	Emit("const CompiledStmt ZAM::" + m + suffix + "(" + decls + ")");
	BeginBlock();

	InstantiateMethodCore(ot, suffix, is_field, is_vec, is_cond);

	if ( HasPostMethod() )
		Emit(GetPostMethod());

	if ( ! HasCustomMethod() )
		Emit("return AddInst(z);");

	EndBlock();
	NL();
	}

void ZAM_OpTemplate::InstantiateMethodCore(const vector<ZAM_OperandType>& ot,
					   string suffix, bool is_field,
					   bool is_vec, bool is_cond)
	{
	if ( HasCustomMethod() )
		{
		Emit(GetCustomMethod());
		return;
		}

	assert(ot.size() > 0);

	auto op = g->GenOpCode(this, "_" + OpString(ot) + suffix, is_field);

	Emit("ZInstI z;");

	if ( ot[0] == ZAM_OT_AUX )
		{
                Emit("z = ZInstI(" + op + ");");
		return;
		}

	if ( ot[0] == ZAM_OT_NONE )
		{
		Emit("z = GenInst(this, " + op + ");");
		return;
		}

	if ( ot.size() > 1 && ot[1] == ZAM_OT_AUX )
                {
                Emit("z = ZInstI(" + op + ", Frame1Slot(n, " + op + "));");
		return;
                }

	ArgsManager args(ot, is_cond);

	auto params = args.Params();

	if ( is_field )
		{
		params += ", i";
		Emit("auto field = f->Field();");
		}

	BuildInstruction(op, ot, params, is_cond);

	auto tp = GetTypeParam();
	if ( tp > 0 )
		Emit("z.SetType(" + args.NthParam(tp - 1) + "->Type());");

	auto tp2 = GetType2Param();
	if ( tp2 > 0 )
		Emit("z.t2 = " + args.NthParam(tp2 - 1) + "->Type();");
	}

void ZAM_OpTemplate::BuildInstruction(const string& op,
			              const vector<ZAM_OperandType>& ot,
                                      const string& params, bool is_cond)
	{
	Emit("z = GenInst(this, " + op + ", " + params + ");");
	}

void ZAM_OpTemplate::InstantiateEval(const vector<ZAM_OperandType>& ot,
                                     const string& suffix,
                                     bool is_field, bool is_vec, bool is_cond)
	{
	InstantiateEval(Eval, OpString(ot) + suffix, GetEval(), is_field);
	}

void ZAM_OpTemplate::InstantiateEval(EmitTarget et, const string& op_suffix,
                                     const string& eval, bool is_field)
	{
	auto op_code = g->GenOpCode(this, "_" + op_suffix, is_field);

	EmitTo(et);
	Emit("case " + op_code + ":");
	BeginBlock();
	Emit(eval);
	EndBlock();
	EmitUp("break;");
	NL();
	}

void ZAM_OpTemplate::InstantiateAssignOp(const vector<ZAM_OperandType>& ot,
                                         const string& suffix)
	{
	// First, create a generic version of the operand, which the
	// ZAM compiler uses to find specific-flavored versions.
	auto op_string = "_" + OpString(ot);
	auto generic_op = g->GenOpCode(this, op_string);
	auto flavor_ind = "assignment_flavor[" + generic_op + "]";

	EmitTo(AssignFlavor);
	Emit(flavor_ind + " = empty_map;");

	auto eval = GetEval();
	auto v = GetAssignVal();

	for ( auto& ti : ZAM_type_info )
		{
		auto op = g->GenOpCode(this, op_string + "_" + ti.suffix);

		if ( IsInternalOp() )
			{
			EmitTo(AssignFlavor);
			Emit(flavor_ind + "[" + ti.tag + "] = " + op + ";");

			if ( HasAssignmentLess() )
				{
				Emit("assignmentless_op[" + op + "] = " +
				     AssignmentLessOp() + ";");
				Emit("assignmentless_op_type[" + op + "] = " +
				     AssignmentLessOpType() + ";");
				}
			}

		EmitTo(Eval);
		Emit("case " + op + ":");
		BeginBlock();
		GenAssignOpCore(ot, eval, ti.accessor, ti.is_managed);
		Emit("break;");
		EndBlock();
		}
	}

void ZAM_OpTemplate::GenAssignOpCore(const vector<ZAM_OperandType>& ot,
                                     const string& eval,
                                     const string& accessor, bool is_managed)
	{
	auto acc = "." + accessor + "_val";

	if ( HasAssignVal() )
		{
		auto v = GetAssignVal();

		Emit(eval);

		if ( is_managed )
			{
			auto val_accessor = accessor;
			auto& Va1 = val_accessor.front();
			Va1 = toupper(Va1);

			Emit("auto& v1 = frame[z.v1]" + acc + ";");
			Emit("Unref(v1);");
			Emit("v1 = " + v + "->As" + val_accessor + "Val();");
			Emit("::Ref(v1);");
			}
		else
			Emit("frame[z.v1]" + acc + " = " +
			     v + "->val" + acc + ";");

		return;
		}

	auto lhs_field = (ot[0] == ZAM_OT_FIELD);
	auto rhs_field = lhs_field && (ot[1] == ZAM_OT_FIELD);

	int op2_offset = rhs_field ? 2 : 1;
	auto constant_op = (ot[op2_offset] == ZAM_OT_CONSTANT);

	string rhs = constant_op ? "z.c" : "frame[z.v2]";

	if ( rhs_field )
		{
		auto lhs_offset = constant_op ? 2 : 3;
		auto rhs_offset = lhs_offset + 1;

		Emit("auto v = " + rhs +
		     ".record_val->RawFields()->Lookup(z.v" +
		     to_string(rhs_offset) + ", ZAM_error);");

		Emit("if ( ZAM_error )");
		EmitUp("ZAM_run_time_error(z.loc, \"field value missing\");");
		Emit("else");

		BeginBlock();
		if ( is_managed )
			Emit("::Ref(v" + acc + ");");

		Emit("frame[z.v1].record_val->RawFields()->Assign(z.v" +
		     to_string(lhs_offset) + ", v);");
		EndBlock();
		}

	else
		{
		if ( is_managed )
			Emit("::Ref(" + rhs + acc + ");");

		if ( lhs_field )
			{
			auto lhs_offset = constant_op ? 2 : 3;

			Emit("frame[z.v1].record_val->RawFields()->Assign(z.v" +
			     to_string(lhs_offset) + ", " + rhs + ");");
			}

		else
			{
			if ( is_managed )
				Emit("Unref(frame[z.v1]" + acc + ");");

			Emit("frame[z.v1]" + acc + " = " + rhs + acc + ";");
			}
		}
	}

string ZAM_OpTemplate::MethodName(const vector<ZAM_OperandType>& ot) const
	{
	return base_name + OpString(ot);
	}

string ZAM_OpTemplate::MethodDecl(const vector<ZAM_OperandType>& ot_orig,
                                  bool is_field, bool is_cond)
	{
	auto ot = ot_orig;
	if ( is_field )
		ot.emplace_back(ZAM_OT_INT);

	ArgsManager args(ot, is_cond);
	return args.Decls();
	}

string ZAM_OpTemplate::OpString(const vector<ZAM_OperandType>& ot) const
	{
	string os;
	for ( auto& o : ot )
		os += ot_to_char[o];
	return os;
	}

string ZAM_OpTemplate::SkipWS(const string& s) const
	{
	auto sp = s.c_str();
	while ( *sp && isspace(*sp) )
		++sp;

	return sp;
	}

void ZAM_OpTemplate::Emit(const string& s)
	{
	g->Emit(curr_et, s);
	}

void ZAM_OpTemplate::EmitNoNL(const string& s)
	{
	g->SetNoNL(true);
	Emit(s);
	g->SetNoNL(false);
	}

void ZAM_OpTemplate::IndentUp()
	{
	g->IndentUp();
	}

void ZAM_OpTemplate::IndentDown()
	{
	g->IndentDown();
	}


void ZAM_UnaryOpTemplate::Instantiate()
	{
	UnaryInstantiate();
	}

void ZAM_DirectUnaryOpTemplate::Instantiate()
	{
	EmitTo(DirectDef);
	Emit("case EXPR_" + cname + ":\treturn c->" + direct + "(lhs, rhs);");
	}

static unordered_map<char, ZAM_ExprType> expr_type_names = {
	{ '*', ZAM_EXPR_TYPE_ANY },
	{ 'A', ZAM_EXPR_TYPE_ADDR },
	{ 'D', ZAM_EXPR_TYPE_DOUBLE },
	{ 'I', ZAM_EXPR_TYPE_INT },
	{ 'N', ZAM_EXPR_TYPE_SUBNET },
	{ 'P', ZAM_EXPR_TYPE_PATTERN },
	{ 'S', ZAM_EXPR_TYPE_STRING },
	{ 'T', ZAM_EXPR_TYPE_TABLE },
	{ 'U', ZAM_EXPR_TYPE_UINT },
	{ 'V', ZAM_EXPR_TYPE_VECTOR },
	{ 'X', ZAM_EXPR_TYPE_NONE },
};

// Inverse of the above.
static unordered_map<ZAM_ExprType, char> expr_name_types;

ZAM_ExprOpTemplate::ZAM_ExprOpTemplate(ZAMGen* _g, string _base_name)
: ZAM_OpTemplate(_g, _base_name)
	{
	static bool did_map_init = false;

	if ( ! did_map_init )
		{
		for ( auto& tn : expr_type_names )
			expr_name_types[tn.second] = tn.first;

		did_map_init = true;
		}
	}

void ZAM_ExprOpTemplate::Parse(const string& attr, const string& line,
                               const Words& words)
	{
	if ( attr == "op-type" )
		{
		if ( words.size() == 1 )
			g->Gripe("op-type needs arguments", line);

		for ( auto i = 1; i < words.size(); ++i )
			{
			auto& w_i = words[i];
			if ( w_i.size() != 1 )
				g->Gripe("bad op-type argument", w_i);

			auto et_c = w_i.c_str()[0];
			if ( expr_type_names.count(et_c) == 0 )
				g->Gripe("bad op-type argument", w_i);

			AddExprType(expr_type_names[et_c]);
			}
		}

	else if ( attr == "includes-field-op" )
		{
		if ( words.size() != 1 )
			g->Gripe("includes-field-op does not take any arguments", line);

		SetIncludesFieldOp();
		}

	else if ( attr == "eval-type" )
		{
		if ( words.size() < 3 )
			g->Gripe("eval-type needs type and evaluation", line);

		auto& type = words[1];
		if ( type.size() != 1 )
			g->Gripe("bad eval-type type", type);

		auto type_c = type.c_str()[0];
		if ( expr_type_names.count(type_c) == 0 )
			g->Gripe("bad eval-type type", type);

		auto et = expr_type_names[type_c];

		if ( expr_types.count(et) == 0 )
			g->Gripe("eval-type type not present in eval-type", type);

		auto eval = g->SkipWords(line, 2);
		eval += GatherEval();
		AddEvalSet(et, eval);
		}

	else if ( attr == "eval-mixed" )
		{
		if ( words.size() < 4 )
			g->Gripe("eval-mixed needs types and evaluation", line);

		auto& type1 = words[1];
		auto& type2 = words[2];
		if ( type1.size() != 1 || type2.size() != 1 )
			g->Gripe("bad eval-mixed types", line);

		auto type_c1 = type1.c_str()[0];
		auto type_c2 = type2.c_str()[0];
		if ( expr_type_names.count(type_c1) == 0 ||
		     expr_type_names.count(type_c2) == 0 )
			g->Gripe("bad eval-mixed types", line);

		auto et1 = expr_type_names[type_c1];
		auto et2 = expr_type_names[type_c2];

		auto eval = g->SkipWords(line, 3);
		eval += GatherEval();
		AddEvalSet(et1, et2, eval);
		}

	else if ( attr == "eval-pre" )
		{
		if ( words.size() < 2 )
			g->Gripe("eval-pre needs evaluation", line);

		auto eval = g->SkipWords(line, 1);
		eval += GatherEval();

		SetPreEval(eval);
		}

	else
		ZAM_OpTemplate::Parse(attr, line, words);
	}

void ZAM_ExprOpTemplate::Instantiate()
	{
	InstantiateOp(OperandTypes(), IncludesVectorOp());

	if ( op_types.size() > 1 && op_types[1] == ZAM_OT_CONSTANT )
		InstantiateC1(op_types, op_types.size() - 1);
	if ( op_types.size() > 2 && op_types[2] == ZAM_OT_CONSTANT )
		InstantiateC2(op_types, op_types.size() - 1);
	if ( op_types.size() > 3 && op_types[3] == ZAM_OT_CONSTANT )
		InstantiateC3(op_types);

	bool all_var = true;
	for ( auto i = 1; i < op_types.size(); ++i )
		if ( op_types[i] != ZAM_OT_VAR )
			all_var = false;

	if ( all_var )
		InstantiateV(op_types);

	if ( op_types.size() == 3 &&
	     op_types[1] == ZAM_OT_RECORD_FIELD && op_types[2] == ZAM_OT_INT)
		InstantiateV(op_types);
	}

void ZAM_ExprOpTemplate::InstantiateC1(const vector<ZAM_OperandType>& ots,
                                       int arity, bool do_vec)
	{
	string args = "lhs, r1->AsConstExpr()";

	if ( arity == 1 && ots[0] == ZAM_OT_RECORD_FIELD )
		args += ", rhs->AsFieldExpr()";

	else if ( arity > 1 )
		{
		args += ", ";

		if ( ots[2] == ZAM_OT_RECORD_FIELD )
			args += "rhs->AsFieldExpr()";
		else
			args += "r2->AsNameExpr()";
		}

	auto m = MethodName(ots);

	EmitTo(C1Def);

	EmitNoNL("case EXPR_" + cname + ":");

	if ( do_vec )
		DoVectorCase(m, args);
	else
		EmitUp("return c->" + m + "(" + args + ");");

	if ( IncludesFieldOp() )
		{
		EmitTo(C1FieldDef);
		Emit("case EXPR_" + cname + ":\treturn c->" + m +
		     "_field(" + args + ", field);");
		}
	}

void ZAM_ExprOpTemplate::InstantiateC2(const vector<ZAM_OperandType>& ots,
                                       int arity)
	{
	string args = "lhs, r1->AsNameExpr(), r2->AsConstExpr()";

	if ( arity == 3 )
		args += ", r3->AsNameExpr()";

	auto method = MethodName(ots);
	auto m = method.c_str();

	EmitTo(C2Def);
	Emit("case EXPR_" + cname + ":\treturn c->" + m + "(" + args + ");");

	if ( IncludesFieldOp() )
		{
		EmitTo(C2FieldDef);
		Emit("case EXPR_" + cname + ":\treturn c->" +
		     m + "_field(" + args + ", field);");
		}
	}

void ZAM_ExprOpTemplate::InstantiateC3(const vector<ZAM_OperandType>& ots)
	{
	EmitTo(C3Def);
	Emit("case EXPR_" + cname + ":\treturn c->" + MethodName(ots) +
	     "(lhs, r1->AsNameExpr(), r2->AsNameExpr(), r3->AsConstExpr());");
	}

void ZAM_ExprOpTemplate::InstantiateV(const vector<ZAM_OperandType>& ots)
	{
	auto m = MethodName(ots);

	string args = "lhs, r1->AsNameExpr()";

	if ( ots[0] == ZAM_OT_RECORD_FIELD )
		args += ", rhs->AsFieldExpr()";

	if ( ots.size() >= 3 )
		{
		if ( ots[2] == ZAM_OT_INT )
			args += ", rhs->AsHasFieldExpr()->Field()";
		else
			args += ", r2->AsNameExpr()";

		if ( ots.size() == 4 )
			args += ", r3->AsNameExpr()";
		}

	EmitTo(VDef);
	EmitNoNL("case EXPR_" + cname + ":");

	if ( IncludesVectorOp() )
		DoVectorCase(m, args);
	else
		EmitUp("return c->" + m + "(" + args + ");");

	if ( IncludesFieldOp() )
		{
		EmitTo(VFieldDef);
		Emit("case EXPR_" + cname + ":\treturn c->" + m + "_field(" +
		     args + ", field);");
		}
	}

void ZAM_ExprOpTemplate::DoVectorCase(const string& m, const string& args)
	{
	NL();
	IndentUp();
	Emit("if ( rt->Tag() == TYPE_VECTOR )");
	EmitUp("return c->" + m + "_vec(" + args + ");");
	Emit("else");
	EmitUp("return c->" + m + "(" + args + ");");
	IndentDown();
	}

void ZAM_ExprOpTemplate::BuildInstructionCore(const string& op,
                                              const string& params)
	{
	const auto& ets = ExprTypes();

	Emit("auto tag = t->Tag();");
	Emit("auto i_t = t->InternalType();");

	static map<ZAM_ExprType, pair<string, string>> if_tests = {
		{ ZAM_EXPR_TYPE_ADDR, { "i_t", "TYPE_INTERNAL_ADDR" } },
		{ ZAM_EXPR_TYPE_DOUBLE, { "i_t", "TYPE_INTERNAL_DOUBLE" } },
		{ ZAM_EXPR_TYPE_INT, { "i_t", "TYPE_INTERNAL_INT" } },
		{ ZAM_EXPR_TYPE_UINT, { "i_t", "TYPE_INTERNAL_UNSIGNED" } },
		{ ZAM_EXPR_TYPE_PATTERN, { "tag", "TYPE_PATTERN" } },
		{ ZAM_EXPR_TYPE_STRING, { "i_t", "TYPE_INTERNAL_STRING" } },
		{ ZAM_EXPR_TYPE_SUBNET, { "i_t", "TYPE_INTERNAL_SUBNET" } },
		{ ZAM_EXPR_TYPE_TABLE, { "tag", "TYPE_TABLE" } },
		{ ZAM_EXPR_TYPE_VECTOR, { "tag", "TYPE_VECTOR" } },

		{ ZAM_EXPR_TYPE_ANY, { "", "" } },
	};

	bool do_default = false;
	int ncases = 0;

	for ( auto et : ets )
		{
		if ( if_tests.count(et) == 0 )
			g->Gripe("bad op-type", op_loc);

		auto if_test = if_tests[et];
		auto if_var = if_test.first;
		auto if_val = if_test.second;

		if ( if_var.size() == 0 )
			{
			do_default = true;
			continue;
			}

		auto if_stmt = "if ( " + if_var + " == " + if_val + " )";
		if ( ++ncases > 1 )
			if_stmt = "else " + if_stmt;

		Emit(if_stmt);

		auto inst = op + "_" + expr_name_types[et];
		EmitUp("z = GenInst(this, " + inst + ", " + params + ");");
		}

	if ( do_default )
		{
		Emit("else");
		EmitUp("z = GenInst(this, " + op + ", " + params + ");");
		}
	}

void ZAM_ExprOpTemplate::InstantiateEval(const vector<ZAM_OperandType>& ot,
                                         const string& suffix, bool is_field,
                                         bool is_vec, bool is_cond)
	{
	if ( expr_types.size() == 0 )
		{ // No operand types to expand over.
		ZAM_OpTemplate::InstantiateEval(ot, suffix, is_field, is_vec, is_cond);
		return;
		}

	auto ot_str = OpString(ot);

	// Some of these might not wind up being used, but no harm in
	// initializing them in cse they are.
	string lhs, op1, op2;
	string branch_target = "z.v";

	EmitTarget emit_target = Eval;

	if ( is_vec )
		{
		lhs = "vec1[i]";
		op1 = "vec2[i]";
		op2 = "vec3[i]";

		emit_target = Arity() == 1 ? Vec1Eval : Vec2Eval;
		}

	else
		{
		lhs = "frame[z.v1]";

		auto op2_offset = 3;
		bool ot1_const = ot[1] == ZAM_OT_CONSTANT;
		bool ot2_const = Arity() >= 2 && ot[2] == ZAM_OT_CONSTANT;

		if ( ot1_const )
			{
			op1 = "z.c";
			--op2_offset;
			branch_target += "2";
			}
		else
			{
			op1 = "frame[z.v2]";

			if ( Arity() > 1 && ot[2] == ZAM_OT_VAR )
				branch_target += "3";
			else
				branch_target += "2";
			}

		if ( ot2_const )
			op2 = "z.c";
		else
			op2 = "frame[z.v" + to_string(op2_offset) + "]";

		if ( is_field )
			{
			// Compute the slot holding the field offset.

			auto f =
				// The first slots are taken up by the
				// assignment slot and the operands ...
				Arity() + 1 +
				// ... and slots are numbered starting at 1.
				+ 1;

			if ( ot1_const || ot2_const )
				// One of the operand slots won't be needed
				// due to the presence of a constant.
				// (It's never the case that both operands
				// are constants - those instead get folded.)
				--f;

			lhs += ".record_val->RawFields()->SetField(z.v" +
			       to_string(f) + ")";
			}
		}

	struct EvalInstance {
		EvalInstance(ZAM_ExprType _lhs_et, ZAM_ExprType _op1_et,
		             ZAM_ExprType _op2_et, string _eval)
			{
			lhs_et = _lhs_et;
			op1_et = _op1_et;
			op2_et = _op2_et;
			eval = move(_eval);
			}

		string LHSAccessor() const
			{
			if ( lhs_et == ZAM_EXPR_TYPE_ANY )
				return "";
			else
				return Accessor(lhs_et);
			}
		string Op1Accessor() const	{ return Accessor(op1_et); }
		string Op2Accessor() const	{ return Accessor(op2_et); }

		string Accessor(ZAM_ExprType et) const
			{
			if ( lhs_et == ZAM_EXPR_TYPE_NONE )
				return "";
			else
				return "." + find_type_info(et).accessor + "_val";
			}

		string OpMarker() const
			{
			if ( op1_et == ZAM_EXPR_TYPE_ANY ||
			     op1_et == ZAM_EXPR_TYPE_NONE )
				return "";
			else if ( op1_et == op2_et )
				return "_" + find_type_info(op1_et).suffix;
			else
				return "_" + find_type_info(op1_et).suffix +
				       find_type_info(op2_et).suffix;
			}

		ZAM_ExprType lhs_et;
		ZAM_ExprType op1_et;
		ZAM_ExprType op2_et;
		string eval;
	};
	vector<EvalInstance> eval_instances;

	for ( auto et : expr_types )
		{
		string eval = eval_set.count(et) > 0 ? eval_set[et] : GetEval();
		auto lhs_et = IsConditional() ? ZAM_EXPR_TYPE_INT : et;
		eval_instances.emplace_back(lhs_et, et, et, eval);
		}

	for ( auto em1 : eval_mixed_set )
		{
		auto et1 = em1.first;
		for ( auto em2 : em1.second )
			{
			auto et2 = em2.first;

			// For the LHS, either its expression type is
			// ignored, or if it's a conditional, so just
			// note it for the latter.
			auto lhs_et = ZAM_EXPR_TYPE_INT;
			eval_instances.emplace_back(lhs_et, et1, et2, em2.second);
			}
		}

	for ( auto& ei : eval_instances )
		{
		auto lhs_accessor = ei.LHSAccessor();
		if ( HasExplicitResultType() )
			lhs_accessor = "";

		auto lhs_ei = lhs + lhs_accessor;
		auto op1_ei = op1 + ei.Op1Accessor();
		auto op2_ei = op2 + ei.Op2Accessor();

		auto eval = SkipWS(ei.eval);

		auto is_none = ei.lhs_et == ZAM_EXPR_TYPE_NONE;
		auto is_star = ei.lhs_et == ZAM_EXPR_TYPE_ANY;

		if ( ! is_field && ! is_none && ! is_star &&
		     find_type_info(ei.lhs_et).is_managed &&
		     ! HasExplicitResultType() )
			{
			auto pre = "auto hold_lhs = " + lhs_ei + ";\n\t";
			auto post = "\tUnref(hold_lhs);";
			eval = pre + eval + post;
			}

		eval = regex_replace(eval, regex("\\$1"), op1_ei);
		eval = regex_replace(eval, regex("\\$2"), op2_ei);

		if ( eval.find("$$") != string::npos )
			eval = regex_replace(eval, regex("\\$\\$"), lhs_ei);

		else if ( is_cond )
			{
			// Aesthetics: get rid of trailing newlines.
			eval = regex_replace(eval, regex("\n"), "");
			eval = "if ( ! (" + eval + ") ) " +
			       "{ pc = " + branch_target + "; continue; }";
			}

		else if ( ! is_none )
			{
			eval = lhs_ei + " = " + eval;

			if ( eval_set.size() == 0 && eval_mixed_set.size() == 0 )
				// Add terminating semicolon.
				eval = regex_replace(eval, regex("\n"), ";\n");
			}

		auto full_suffix = ot_str + ei.OpMarker() + suffix;

		ZAM_OpTemplate::InstantiateEval(emit_target, full_suffix,
		                                eval, is_field);

		if ( is_vec )
			{
			string dispatch_params = "frame[z.v1].vector_val, frame[z.v2].vector_val";

			if ( Arity() == 2 )
				dispatch_params += ", frame[z.v3].vector_val";

			auto op_code = g->GenOpCode(this, "_" + full_suffix,
			                            false);
			auto dispatch = "vec_exec(" + op_code + ", z.t, " +
					dispatch_params + ");";

			ZAM_OpTemplate::InstantiateEval(Eval, full_suffix,
							dispatch, false);
			}
		}
	}


void ZAM_UnaryExprOpTemplate::Parse(const string& attr, const string& line,
                                    const Words& words)
	{
	if ( attr == "no-const" )
		{
		if ( words.size() != 1 )
			g->Gripe("extraneous argument to no-const", line);

		SetNoConst();
		}

	else if ( attr == "explicit-result-type" )
		{
		if ( words.size() != 1 )
			g->Gripe("extraneous argument to explicit-result-type", line);
		SetHasExplicitResultType();
		}

	else
		ZAM_ExprOpTemplate::Parse(attr, line, words);
	}

void ZAM_UnaryExprOpTemplate::Instantiate()
	{
	UnaryInstantiate();

	vector<ZAM_OperandType> ots = { ZAM_OT_VAR, ZAM_OT_CONSTANT };

	if ( ! NoConst() )
		InstantiateC1(ots, 1, IncludesVectorOp());

	ots[1] = ZAM_OT_VAR;
	InstantiateV(ots);
	}

void ZAM_UnaryExprOpTemplate::BuildInstruction(const string& op,
			                       const vector<ZAM_OperandType>& ot,
                                               const string& params,
                                               bool is_cond)
	{
	const auto& ets = ExprTypes();

	if ( ets.size() == 1 && ets.count(ZAM_EXPR_TYPE_NONE) == 1 )
		{
		ZAM_ExprOpTemplate::BuildInstruction(op, ot, params, is_cond);
		return;
		}

	auto constant_op = ot.back() == ZAM_OT_CONSTANT;
	string operand = constant_op ? "c" : "n2";

	if ( ot[0] == ZAM_OT_FIELD )
		{
		operand = constant_op ? "n" : "n1";
		Emit("auto " + operand + " = flhs->GetOp1()->AsNameExpr();");
		Emit("auto t = flhs->Type();");

		string f = ot[1] == ZAM_OT_FIELD ? "field1" : "field";
		Emit("int " + f + " = flhs->Field();");
		}

	else
		Emit("auto t = " + operand + "->Type();");

	BuildInstructionCore(op, params);
	}


ZAM_AssignOpTemplate::ZAM_AssignOpTemplate(ZAMGen* _g, string _base_name)
: ZAM_UnaryExprOpTemplate(_g, _base_name)
	{
	// Assignments apply to every valid form of ExprType.
	for ( auto& etn : expr_type_names )
		{
		auto et = etn.second;
		if ( et != ZAM_EXPR_TYPE_NONE )
			AddExprType(et);
		}
	}

void ZAM_AssignOpTemplate::Parse(const string& attr, const string& line,
                                 const Words& words)
	{
	if ( attr == "field-op" )
		{
		if ( words.size() != 1 )
			g->Gripe("field-op does not take any arguments", line);

		SetFieldOp();
		}

	else
		ZAM_OpTemplate::Parse(attr, line, words);
	}


void ZAM_AssignOpTemplate::Instantiate()
	{
	if ( op_types.size() != 1 )
		g->Gripe("operation needs precisely one \"type\"", op_loc);

	vector<ZAM_OperandType> ots;
	ots.push_back(op_types[0]);

	// Build constant/variable versions ...
	ots.push_back(ZAM_OT_CONSTANT);
	InstantiateOp(ots, false);
	InstantiateC1(ots, 1);

	ots[1] = ZAM_OT_VAR;
	InstantiateOp(ots, false);

	if ( ots[0] != ZAM_OT_FIELD )
		InstantiateV(ots);

	// ... and for assignments to fields, additional field versions.
	if ( ots[0] == ZAM_OT_FIELD )
		{
		ots[1] = ZAM_OT_FIELD;

		ots.push_back(ZAM_OT_CONSTANT);
		InstantiateOp(ots, false);

		ots[2] = ZAM_OT_VAR;
		InstantiateOp(ots, false);
		}
	}


void ZAM_BinaryExprOpTemplate::Instantiate()
	{
	// As usual, the first slot receives the operator's result.
	vector<ZAM_OperandType> ots = { ZAM_OT_VAR };
	ots.resize(3);

	// Build each combination for constant/variable operand,
	// except skip constant/constant as that is always folded.

	// We only include vector operations when both operands
	// are non-constants.

	ots[1] = ZAM_OT_CONSTANT;
	ots[2] = ZAM_OT_VAR;
	InstantiateOp(ots, false);

	if ( ! IsInternalOp() )
		InstantiateC1(ots, 2, false);

	ots[1] = ZAM_OT_VAR;
	ots[2] = ZAM_OT_CONSTANT;
	InstantiateOp(ots, false);

	if ( ! IsInternalOp() )
		InstantiateC2(ots, 2);

	ots[2] = ZAM_OT_VAR;
	InstantiateOp(ots, IncludesVectorOp());

	if ( ! IsInternalOp() )
		InstantiateV(ots);
	}


void ZAM_RelationalExprOpTemplate::Instantiate()
	{
	ZAM_BinaryExprOpTemplate::Instantiate();

	EmitTo(Cond);

	Emit("case EXPR_" + cname + ":");
	IndentUp();
	Emit("if ( n1 && n2 )");
	EmitUp("return " + cname + "VVV_cond(n1, n2);");
	Emit("else if ( n1 )");
	EmitUp("return " + cname + "VVC_cond(n1, c);");
	Emit("else");
	EmitUp("return " + cname + "VCV_cond(c, n2);");
	IndentDown();
	NL();
	}

void ZAM_RelationalExprOpTemplate::BuildInstruction(const string& op,
			                            const vector<ZAM_OperandType>& ot,
                                                    const string& params,
						    bool is_cond)
	{
	string op1 = is_cond ? "n" : "n2";
	Emit("auto t = " + op1 + "->Type();");
	BuildInstructionCore(op, params);
	}


void ZAM_InternalBinaryOpTemplate::Parse(const string& attr, const string& line,
                                         const Words& words)
	{
	if ( attr == "op-accessor" )
		{
		if ( words.size() != 2 )
			g->Gripe("op-accessor takes one argument", line);

		SetOpAccessor(words[1]);
		}

	else if ( attr == "op1-accessor" )
		{
		if ( words.size() != 2 )
			g->Gripe("op-accessor1 takes one argument", line);

		SetOp1Accessor(words[1]);
		}

	else if ( attr == "op2-accessor" )
		{
		if ( words.size() != 2 )
			g->Gripe("op-accessor2 takes one argument", line);

		SetOp2Accessor(words[1]);
		}

	else
		ZAM_BinaryExprOpTemplate::Parse(attr, line, words);
	}


ZAMGen::ZAMGen(int argc, char** argv)
	{
	auto prog_name = argv[0];

	if ( argc != 2 )
		{
		fprintf(stderr, "usage: %s <ZAM-templates-file>\n", prog_name);
		exit(1);
		}

	auto file_name = argv[1];
	auto f = strcmp(file_name, "-") ? fopen(file_name, "r") : stdin;

	if ( ! f )
		{
		fprintf(stderr, "%s: cannot open \"%s\"\n", prog_name, file_name);
		exit(1);
		}

	ti = make_unique<TemplateInput>(f, prog_name, file_name);

	while ( ParseTemplate() )
		;

	for ( auto& t : templates )
		t->Instantiate();
	}

bool ZAMGen::ParseTemplate()
	{
	string line;

	if ( ! ScanLine(line) )
		return false;

	if ( line.size() <= 1 )
		// A blank line - no template to parse.
		return true;

	auto words = SplitIntoWords(line);

	if ( words.size() < 2 )
		Gripe("too few words at start of template", line);

	auto op = words[0];
	auto op_name = words[1];

	// We track issues with the wrong number of template arguments
	// up front, to avoid mis-invoking constructors, but we don't
	// report these until later because if the template names a
	// bad operation, it's better to report that as the core problem.
	const char* args_mismatch = nullptr;

	if ( op == "direct-unary-op" )
		{
		if ( words.size() != 3 )
			args_mismatch = "direct-unary-op takes 2 arguments";
		}
	else if ( words.size() != 2 )
		args_mismatch = "templates take 1 argument";

	unique_ptr<ZAM_OpTemplate> t;

	if ( op == "op" )
		t = make_unique<ZAM_OpTemplate>(this, op_name);
	else if ( op == "unary-op" )
		t = make_unique<ZAM_UnaryOpTemplate>(this, op_name);
	else if ( op == "direct-unary-op" )
		t = make_unique<ZAM_DirectUnaryOpTemplate>(this, op_name, words[2]);
	else if ( op == "assign-op" )
		t = make_unique<ZAM_AssignOpTemplate>(this, op_name);
	else if ( op == "expr-op" )
		t = make_unique<ZAM_ExprOpTemplate>(this, op_name);
	else if ( op == "unary-expr-op" )
		t = make_unique<ZAM_UnaryExprOpTemplate>(this, op_name);
	else if ( op == "binary-expr-op" )
		t = make_unique<ZAM_BinaryExprOpTemplate>(this, op_name);
	else if ( op == "rel-expr-op" )
		t = make_unique<ZAM_RelationalExprOpTemplate>(this, op_name);
	else if ( op == "internal-binary-op" )
		t = make_unique<ZAM_InternalBinaryOpTemplate>(this, op_name);
	else if ( op == "internal-op" )
		t = make_unique<ZAM_InternalOpTemplate>(this, op_name);
	else if ( op == "internal-assignment-op" )
		t = make_unique<ZAM_InternalAssignOpTemplate>(this, op_name);

	else
		Gripe("bad template name", op);

	if ( args_mismatch )
		Gripe(args_mismatch, line);

	t->Build();
	templates.emplace_back(move(t));

	return true;
	}

void ZAMGen::Emit(EmitTarget et, const string& s)
	{
	assert(et != None);

	static unordered_map<EmitTarget, FILE*> gen_files;
	if ( gen_files.size() == 0 )
		{ // need to open the files
		static unordered_map<EmitTarget, const char*> gen_file_names = {
			{ None, nullptr },
			{ BaseDecl, "BaseDecl" },
			{ SubDecl, "SubDecl" },
			{ MethodDef, "MethodDef" },
			{ DirectDef, "DirectDef" },
			{ C1Def, "C1Def" },
			{ C1FieldDef, "C1FieldDef" },
			{ C2Def, "C2Def" },
			{ C2FieldDef, "C2FieldDef" },
			{ C3Def, "C3Def" },
			{ VDef, "VDef" },
			{ VFieldDef, "VFieldDef" },
			{ Cond, "Cond" },
			{ Eval, "Eval" },
			{ Vec1Eval, "Vec1Eval" },
			{ Vec2Eval, "Vec2Eval" },
			{ AssignFlavor, "AssignFlavor" },
			{ Op1Flavor, "Op1Flavor" },
			{ OpSideEffects, "OpSideEffects" },
			{ OpDef, "OpDef" },
			{ OpName, "OpName" },
		};

		for ( auto& gfn : gen_file_names )
			{
			auto fn = gfn.second;
			if ( ! fn )
				continue;

			auto f = fopen(fn, "w");
			if ( ! f )
				{
				fprintf(stderr, "can't open generation file %s\n", fn);
				exit(1);
				}

			gen_files[gfn.first] = f;
			}
		}

	if ( gen_files.count(et) == 0 )
		{
		fprintf(stderr, "bad generation file type\n");
		exit(1);
		}

	FILE* f = gen_files[et];

	for ( auto i = indent_level; i > 0; --i )
		fputs("\t", f);

	fputs(s.c_str(), f);

	if ( s.back() != '\n' && ! no_NL )
		fputs("\n", f);
	}

string ZAMGen::GenOpCode(const ZAM_OpTemplate* ot, const string& suffix,
                         bool is_field)
	{
	auto op = "OP_" + ot->CanonicalName() + suffix;

	static unordered_set<string> known_opcodes;

	if ( known_opcodes.count(op) > 0 )
		return op;

	known_opcodes.insert(op);

	IndentUp();

	Emit(OpDef, op + ",");

	auto op_comment = ",\t// " + op;
	auto flavor = is_field ? "OP1_READ" : ot->GetOp1Flavor();
	Emit(Op1Flavor, flavor + op_comment);

	auto se = ot->HasSideEffects() ? "true" : "false";
	Emit(OpSideEffects, se + op_comment);

	auto name = ot->BaseName();
	transform(name.begin(), name.end(), name.begin(), ::tolower);
	name += suffix;
	transform(name.begin(), name.end(), name.begin(), under_to_dash);
	Emit(OpName, "case " + op + ":\treturn \"" + name + "\";");

	IndentDown();

	return op;
	}


bool TemplateInput::ScanLine(string& line)
	{
	if ( put_back.size() > 0 )
		{
		line = put_back;
		put_back.clear();
		return true;
		}

	char buf[8192];

	// Read lines, discarding comments.
	do {
		if ( ! fgets(buf, sizeof buf, f) )
			return false;
		++loc.line_num;
	} while ( buf[0] == '#' );

	line = buf;
	return true;
	}

vector<string> TemplateInput::SplitIntoWords(const string& line) const
	{
	vector<string> words;

	for ( auto start = line.c_str(); *start && *start != '\n'; )
		{
		auto end = start + 1;
		while ( *end && ! isspace(*end) )
			++end;

		words.emplace_back(string(start, end - start));

		start = end;
		while ( *start && isspace(*start) )
			++start;
		}

	return words;
	}

string TemplateInput::SkipWords(const string& line, int n) const
	{
	auto s = line.c_str();

	for ( int i = 0; i < n; ++i )
		{
		// Find end of current word.
		while ( *s && *s != '\n' )
			{
			if ( isspace(*s) )
				break;
			++s;
			}

		if ( *s == '\n' )
			break;

		// Find start of next word.
		while ( *s && isspace(*s) )
			++s;
		}

	return string(s);
	}

void TemplateInput::Gripe(const char* msg, const string& input)
	{
	auto input_s = input.c_str();
	int n = strlen(input_s);

	fprintf(stderr, "%s, line %d: %s - %s",
	        loc.file_name, loc.line_num, msg, input_s);
	if ( n == 0 || input_s[n-1] != '\n' )
		fprintf(stderr, "\n");

	exit(1);
	}

void TemplateInput::Gripe(const char* msg, const InputLoc& l)
	{
	fprintf(stderr, "%s, line %d: %s\n", l.file_name, l.line_num, msg);
	exit(1);
	}


int main(int argc, char** argv)
	{
	ZAMGen(argc, argv);
	exit(0);
	}
