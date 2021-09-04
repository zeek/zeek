// See the file "COPYING" in the main distribution directory for copyright.

#include <ctype.h>
#include <regex>

#include "zeek/script_opt/ZAM/Gen-ZAM.h"

using namespace std;

// Helper functions to convert dashes to underscores or vice versa.
static char dash_to_under(char c)
	{
	return c == '-' ? '_' : c;
	}

static char under_to_dash(char c)
	{
	return c == '_' ? '-' : c;
	}


// Structure for binding together Zeek script types, internal names Gen-ZAM
// uses to track them, mnemonics for referring to them in instruction names,
// the corresponding Val accessor, and whether the type requires memory
// management.
struct TypeInfo {
	string tag;
	ZAM_ExprType et;
	string suffix;
	string accessor;	// doesn't include "As" prefix or "()" suffix
	bool is_managed;
};

static vector<TypeInfo> ZAM_type_info = {
	{ "TYPE_ADDR",		ZAM_EXPR_TYPE_ADDR,	"A", "Addr", true },
	{ "TYPE_ANY",		ZAM_EXPR_TYPE_ANY,	"a", "Any", true },
	{ "TYPE_COUNT",		ZAM_EXPR_TYPE_UINT,	"U", "Count", false },
	{ "TYPE_DOUBLE",	ZAM_EXPR_TYPE_DOUBLE,	"D", "Double", false },
	{ "TYPE_FILE",		ZAM_EXPR_TYPE_FILE,	"f", "File", true },
	{ "TYPE_FUNC",		ZAM_EXPR_TYPE_FUNC,	"F", "Func", true },
	{ "TYPE_INT",		ZAM_EXPR_TYPE_INT,	"I", "Int", false },
	{ "TYPE_LIST",		ZAM_EXPR_TYPE_LIST,	"L", "List", true },
	{ "TYPE_OPAQUE",	ZAM_EXPR_TYPE_OPAQUE,	"O", "Opaque", true },
	{ "TYPE_PATTERN",	ZAM_EXPR_TYPE_PATTERN,	"P", "Pattern", true },
	{ "TYPE_RECORD",	ZAM_EXPR_TYPE_RECORD,	"R", "Record", true },
	{ "TYPE_STRING",	ZAM_EXPR_TYPE_STRING,	"S", "String", true },
	{ "TYPE_SUBNET",	ZAM_EXPR_TYPE_SUBNET,	"N", "SubNet", true },
	{ "TYPE_TABLE",		ZAM_EXPR_TYPE_TABLE,	"T", "Table", true },
	{ "TYPE_TYPE",		ZAM_EXPR_TYPE_TYPE,	"t", "Type", true },
	{ "TYPE_VECTOR",	ZAM_EXPR_TYPE_VECTOR,	"V", "Vector", true },
};

// Given a ZAM_ExprType, returns the corresponding TypeInfo.
const TypeInfo& find_type_info(ZAM_ExprType et)
	{
	assert(et != ZAM_EXPR_TYPE_NONE);

	auto pred = [et] (const TypeInfo& ti) -> bool { return ti.et == et; };
	auto ti = std::find_if(ZAM_type_info.begin(), ZAM_type_info.end(),
	                       pred);

	assert(ti != ZAM_type_info.end());
	return *ti;
	}

// Given a ZAM_ExprType, return its ZVal accessor.  Takes into account
// some naming inconsistencies between ZVal's and Val's.
string find_type_accessor(ZAM_ExprType et)
	{
	switch ( et ) {
	case ZAM_EXPR_TYPE_NONE:
		return "";

	case ZAM_EXPR_TYPE_UINT:
		return "uint_val";

	case ZAM_EXPR_TYPE_PATTERN:
		return "re_val";

	default:
		{
		string acc = find_type_info(et).accessor;
		transform(acc.begin(), acc.end(), acc.begin(), ::tolower);
		return acc + "_val";
		}
	}
	}


// Maps ZAM operand types to pairs of (1) the C++ name used to declare
// the operand in a method declaration, and (2) the variable name to
// use for the operand.
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
	{ ZAM_OT_ASSIGN_FIELD, { "const NameExpr*", "n" } },
};

ArgsManager::ArgsManager(const vector<ZAM_OperandType>& ot, ZAM_InstClass zc)
	{
	int n = 0;
	bool add_field = false;

	for ( const auto& ot_i : ot )
		{
		if ( ot_i == ZAM_OT_NONE )
			{ // it had better be the only operand type
			assert(ot.size() == 1);
			break;
			}

		if ( n++ == 0 && zc == ZIC_COND )
			// Skip the conditional's nominal assignment slot.
			continue;

		// Start off the argument info using the usual case
		// of (1) same method parameter name as GenInst argument,
		// and (2) not requiring a record field.
		auto& arg_i = ot_to_args[ot_i];
		Arg arg = { arg_i.second, arg_i.first, arg_i.second, false };

		if ( ot_i == ZAM_OT_ASSIGN_FIELD )
			{
			arg.is_field = true;

			if ( n == 1 )
				{ // special-case the parameter
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
	// it.  Note, some names only appear multiple times as arguments
	// when invoking methods, but not in the declarations of the methods
	// themselves.
	for ( auto& arg : args )
		{
		auto& decl = arg.decl_name;
		auto& name = arg.param_name;
		bool decl_and_arg_same = decl == name;

		if ( name_count[name] == 1 )
			continue;	// it's unique

		auto n = to_string(++usage_count[name]);
		name += n;
		if ( decl_and_arg_same )
			decl += n;
		}

	// Finally, build the full versions of the declaration and parameters.

	// Tracks how many record fields we're dealing with.
	int num_fields = 0;

	for ( auto& arg : args )
		{
		if ( ! full_decl.empty() )
			full_decl += ", ";

		full_decl += arg.decl_type + " " + arg.decl_name;

		if ( ! full_params.empty() )
			full_params += ", ";

		full_params += arg.param_name;
		params.push_back(arg.param_name);

		if ( arg.is_field )
			++num_fields;
		}

	assert(num_fields <= 2);

	// Add in additional arguments/parameters for record fields.
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
	// Make the base name viable in a C++ name.
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
		if ( words.empty() )
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

void ZAM_OpTemplate::Parse(const string& attr, const string& line,
                           const Words& words)
	{
	int num_args = -1;	// -1 = don't enforce
	int nwords = words.size();

	if ( attr == "type" )
		{
		if ( nwords <= 1 )
			g->Gripe("missing argument", line);

		num_args = 1;

		const char* types = words[1].c_str();
		while ( *types )
			{
			ZAM_OperandType ot = ZAM_OT_NONE;
			switch ( *types ) {
			case 'C':	ot = ZAM_OT_CONSTANT; break;
			case 'F':	ot = ZAM_OT_ASSIGN_FIELD; break;
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
		if ( ! addl.empty() )
			AddEval(addl);
		}

	else if ( attr == "macro" )
		g->ReadMacro(line);

	else
		g->Gripe("unknown template attribute", attr);

	if ( num_args >= 0 && num_args != nwords - 1 )
		g->Gripe("extraneous or missing arguments", line);
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
	if ( arg == "$$" )
		return 1;

	if ( arg[0] != '$' )
		g->Gripe("bad set-type parameter, should be $n", arg);

	int param = atoi(&arg[1]);

	if ( param <= 0 || param > 2 )
		g->Gripe("bad set-type parameter, should be $1 or $2", arg);

	// Convert operand to underlying instruction element, i.e., add
	// one to account for the $$ assignment slot.
	return param + 1;
	}

// Maps an operand type to a character mnemonic used to distinguish
// it from others.
unordered_map<ZAM_OperandType, char> ZAM_OpTemplate::ot_to_char = {
	{ ZAM_OT_AUX, 'O' },
	{ ZAM_OT_CONSTANT, 'C' },
	{ ZAM_OT_EVENT_HANDLER, 'H' },
	{ ZAM_OT_ASSIGN_FIELD, 'F' },
	{ ZAM_OT_INT, 'i' },
	{ ZAM_OT_LIST, 'L' },
	{ ZAM_OT_NONE, 'X' },
	{ ZAM_OT_RECORD_FIELD, 'R' },
	{ ZAM_OT_VAR, 'V' },
};

void ZAM_OpTemplate::InstantiateOp(const vector<ZAM_OperandType>& ot, bool do_vec)
	{
	auto method = MethodName(ot);

	InstantiateOp(method, ot, ZIC_REGULAR);

	if ( IncludesFieldOp() )
		InstantiateOp(method, ot, ZIC_FIELD);

	if ( do_vec )
		InstantiateOp(method, ot, ZIC_VEC);

	if ( IsConditionalOp() )
		InstantiateOp(method, ot, ZIC_COND);
	}

void ZAM_OpTemplate::InstantiateOp(const string& method,
                                   const vector<ZAM_OperandType>& ot,
                                   ZAM_InstClass zc)
	{
	string suffix = "";

	if ( zc == ZIC_FIELD )		suffix = "_field";
	else if ( zc == ZIC_VEC )	suffix = "_vec";
	else if ( zc == ZIC_COND )	suffix = "_cond";

	if ( ! IsInternalOp() )
		InstantiateMethod(method, suffix, ot, zc);

	if ( IsAssignOp() )
		InstantiateAssignOp(ot, suffix);
	else
		{
		InstantiateEval(ot, suffix, zc);

		if ( HasAssignmentLess() )
			{
			auto op_string = "_" + OpSuffix(ot);
			auto op = g->GenOpCode(this, op_string);
			GenAssignmentlessVersion(op);
			}
		}
	}

void ZAM_OpTemplate::GenAssignmentlessVersion(string op)
	{
	EmitTo(AssignFlavor);
	Emit("assignmentless_op[" + op + "] = " + AssignmentLessOp() + ";");
	Emit("assignmentless_op_type[" + op + "] = " +
	     AssignmentLessOpType() + ";");
	}

void ZAM_OpTemplate::InstantiateMethod(const string& m, const string& suffix,
                                       const vector<ZAM_OperandType>& ot_orig,
                                       ZAM_InstClass zc)
	{
	if ( IsInternalOp() )
		return;

	auto ot = ot_orig;
	if ( zc == ZIC_FIELD )
		// Need to make room for the field offset.
		ot.emplace_back(ZAM_OT_INT);

	auto decls = MethodDeclare(ot, zc);

	EmitTo(MethodDecl);
	Emit("const ZAMStmt " + m + suffix + "(" + decls + ");");

	EmitTo(MethodDef);
	Emit("const ZAMStmt ZAMCompiler::" + m + suffix + "(" + decls + ")");
	BeginBlock();

	InstantiateMethodCore(ot, suffix, zc);

	if ( HasPostMethod() )
		Emit(GetPostMethod());

	if ( ! HasCustomMethod() )
		Emit("return AddInst(z);");

	EndBlock();
	NL();
	}

void ZAM_OpTemplate::InstantiateMethodCore(const vector<ZAM_OperandType>& ot,
					   string suffix, ZAM_InstClass zc)
	{
	if ( HasCustomMethod() )
		{
		Emit(GetCustomMethod());
		return;
		}

	assert(! ot.empty());

	string full_suffix = "_" + OpSuffix(ot) + suffix;

	Emit("ZInstI z;");

	if ( ot[0] == ZAM_OT_AUX )
		{
		auto op = g->GenOpCode(this, full_suffix, zc);
                Emit("z = ZInstI(" + op + ");");
		return;
		}

	if ( ot[0] == ZAM_OT_NONE )
		{
		auto op = g->GenOpCode(this, full_suffix, zc);
		Emit("z = GenInst(" + op + ");");
		return;
		}

	if ( ot.size() > 1 && ot[1] == ZAM_OT_AUX )
                {
		auto op = g->GenOpCode(this, full_suffix, zc);
                Emit("z = ZInstI(" + op + ", Frame1Slot(n, " + op + "));");
		return;
                }

	ArgsManager args(ot, zc);
	BuildInstruction(ot, args.Params(), full_suffix, zc);

	auto tp = GetTypeParam();
	if ( tp > 0 )
		Emit("z.SetType(" + args.NthParam(tp - 1) + "->GetType());");

	auto tp2 = GetType2Param();
	if ( tp2 > 0 )
		Emit("z.t2 = " + args.NthParam(tp2 - 1) + "->GetType();");
	}

void ZAM_OpTemplate::BuildInstruction(const vector<ZAM_OperandType>& ot,
                                      const string& params,
                                      const string& suffix, ZAM_InstClass zc)
	{
	auto op = g->GenOpCode(this, suffix, zc);
	Emit("z = GenInst(" + op + ", " + params + ");");
	}

void ZAM_OpTemplate::InstantiateEval(const vector<ZAM_OperandType>& ot,
                                     const string& suffix, ZAM_InstClass zc)
	{
	auto eval = GetEval();

	if ( ot.size() > 1 )
		{ // Check for use of "$1" to indicate the operand
		string op1;
		if ( ot[1] == ZAM_OT_CONSTANT )
			op1 = "z.c";
		else if ( ot[1] == ZAM_OT_VAR )
			op1 = "frame[z.v2]";

		eval = regex_replace(eval, regex("\\$1"), op1);
		}

	InstantiateEval(Eval, OpSuffix(ot) + suffix, eval, zc);
	}

void ZAM_OpTemplate::InstantiateEval(EmitTarget et, const string& op_suffix,
                                     const string& eval, ZAM_InstClass zc)
	{
	auto op_code = g->GenOpCode(this, "_" + op_suffix, zc);

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
	auto op_string = "_" + OpSuffix(ot);
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
				GenAssignmentlessVersion(op);
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
	if ( HasAssignVal() )
		{
		GenAssignOpValCore(eval, accessor, is_managed);
		return;
		}

	if ( ! eval.empty() )
		g->Gripe("assign-op should not have an \"eval\"", eval);

	auto lhs_field = (ot[0] == ZAM_OT_ASSIGN_FIELD);
	auto rhs_field = lhs_field && ot.size() > 2 && (ot[2] == ZAM_OT_INT);
	auto constant_op = (ot[1] == ZAM_OT_CONSTANT);

	string rhs = constant_op ? "z.c" : "frame[z.v2]";

	auto acc = ".As" + accessor + "()";

	if ( accessor == "Any" && constant_op && ! rhs_field )
		{
		// "any_val = constant" or "x$any_val = constant".
		//
		// These require special-casing, because to avoid going
		// through a CoerceToAny operation, we allow expressing
		// these directly.  They don't fit with the usual assignment
		// paradigm since the RHS differs in type from the LHS.
		Emit("auto v = z.c.ToVal(z.t);");

		if ( lhs_field )
			{
			Emit("auto r = frame[z.v1].AsRecord();");
			Emit("auto& f = r->RawField(z.v2);");
			}
		else
			Emit("auto& f = frame[z.v1];");

		Emit("zeek::Unref(f.ManagedVal());");
		Emit("f = ZVal(v.release());");
		}

	else if ( rhs_field )
		{
		// The following is counter-intuitive, but comes from the
		// fact that we build out the instruction parameters as
		// an echo of the method parameters, and for this case that
		// means that the RHS field offset comes *before*, not after,
		// the LHS field offset.
		auto lhs_offset = constant_op ? 3 : 4;
		auto rhs_offset = lhs_offset - 1;

		Emit("auto v = " + rhs + ".AsRecord()->RawOptField(z.v" +
		     to_string(rhs_offset) +
		     "); // note, RHS field before LHS field");

		Emit("if ( ! v )");
		BeginBlock();
		Emit("ZAM_run_time_error(z.loc, \"field value missing\");");
		Emit("break;");
		EndBlock();

		auto slot = "z.v" + to_string(lhs_offset);
		Emit("auto r = frame[z.v1].AsRecord();");
		Emit("auto& f = r->RawField(" +
		     slot + "); // note, LHS field after RHS field");

		if ( is_managed )
			{
			Emit("zeek::Ref((*v)" + acc + ");");
			Emit("zeek::Unref(f.ManagedVal());");
			}

		Emit("f = *v;");
		}

	else
		{
		if ( is_managed )
			Emit("zeek::Ref(" + rhs + acc + ");");

		if ( lhs_field )
			{
			auto lhs_offset = constant_op ? 2 : 3;
			auto slot = "z.v" + to_string(lhs_offset);
			Emit("auto r = frame[z.v1].AsRecord();");
			Emit("auto& f = r->RawField(" + slot + ");");

			if ( is_managed )
				Emit("zeek::Unref(f.ManagedVal());");

			Emit("f = " + rhs + ";");
			}

		else
			{
			if ( is_managed )
				Emit("zeek::Unref(frame[z.v1].ManagedVal());");

			Emit("frame[z.v1] = ZVal(" + rhs + acc + ");");
			}
		}

	if ( lhs_field )
		Emit("r->Modified();");
	}

void ZAM_OpTemplate::GenAssignOpValCore(const string& eval,
                                        const string& accessor, bool is_managed)
	{
	auto v = GetAssignVal();

	Emit(eval);

	// Maps Zeek types to how to get the underlying value from a ValPtr.
	static unordered_map<string, string> val_accessors = {
		{ "Addr", "->AsAddrVal()" },
		{ "Any", ".get()" },
		{ "Count", "->AsCount()" },
		{ "Double", "->AsDouble()" },
		{ "Int", "->AsInt()" },
		{ "Pattern", "->AsPatternVal()" },
		{ "String", "->AsStringVal()" },
		{ "SubNet", "->AsSubNetVal()" },
		{ "Table", "->AsTableVal()" },
		{ "Vector", "->AsVectorVal()" },
		{ "File", "->AsFile()" },
		{ "Func", "->AsFunc()" },
		{ "List", "->AsListVal()" },
		{ "Opaque", "->AsOpaqueVal()" },
		{ "Record", "->AsRecordVal()" },
		{ "Type", "->AsTypeVal()" },
	};

	auto val_accessor = val_accessors[accessor];

	string rhs;
	if ( IsInternalOp() )
		rhs = v + val_accessor;
	else
		rhs = v + ".As" + accessor + "()";

	if ( is_managed )
		{
		Emit("auto rhs = " + rhs + ";");
		Emit("zeek::Ref(rhs);");
		Emit("Unref(frame[z.v1].ManagedVal());");
		Emit("frame[z.v1] = ZVal(rhs);");
		}
	else
		Emit("frame[z.v1] = ZVal(" + rhs + ");");
	}

string ZAM_OpTemplate::MethodName(const vector<ZAM_OperandType>& ot) const
	{
	return base_name + OpSuffix(ot);
	}

string ZAM_OpTemplate::MethodDeclare(const vector<ZAM_OperandType>& ot,
                                     ZAM_InstClass zc)
	{
	ArgsManager args(ot, zc);
	return args.Decls();
	}

string ZAM_OpTemplate::OpSuffix(const vector<ZAM_OperandType>& ot) const
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
	Emit("case EXPR_" + cname + ":\treturn " + direct + "(lhs, rhs);");
	}

// Maps op-type mnemonics to the corresponding internal value used by Gen-ZAM.
static unordered_map<char, ZAM_ExprType> expr_type_names = {
	{ '*', ZAM_EXPR_TYPE_DEFAULT },
	{ 'A', ZAM_EXPR_TYPE_ADDR },
	{ 'a', ZAM_EXPR_TYPE_ANY },
	{ 'D', ZAM_EXPR_TYPE_DOUBLE },
	{ 'f', ZAM_EXPR_TYPE_FILE },
	{ 'F', ZAM_EXPR_TYPE_FUNC },
	{ 'I', ZAM_EXPR_TYPE_INT },
	{ 'L', ZAM_EXPR_TYPE_LIST },
	{ 'X', ZAM_EXPR_TYPE_NONE },
	{ 'O', ZAM_EXPR_TYPE_OPAQUE },
	{ 'P', ZAM_EXPR_TYPE_PATTERN },
	{ 'R', ZAM_EXPR_TYPE_RECORD },
	{ 'S', ZAM_EXPR_TYPE_STRING },
	{ 'N', ZAM_EXPR_TYPE_SUBNET },
	{ 'T', ZAM_EXPR_TYPE_TABLE },
	{ 't', ZAM_EXPR_TYPE_TYPE },
	{ 'U', ZAM_EXPR_TYPE_UINT },
	{ 'V', ZAM_EXPR_TYPE_VECTOR },
};

// Inverse of the above.
static unordered_map<ZAM_ExprType, char> expr_name_types;

ZAM_ExprOpTemplate::ZAM_ExprOpTemplate(ZAMGen* _g, string _base_name)
: ZAM_OpTemplate(_g, _base_name)
	{
	static bool did_map_init = false;

	if ( ! did_map_init )
		{ // Create the inverse mapping.
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

		if ( eval_set.count(et1) > 0 )
			g->Gripe("eval-mixed uses type also included in op-type", line);

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
		// Not an attribute specific to expr-op's.
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
	     op_types[1] == ZAM_OT_RECORD_FIELD && op_types[2] == ZAM_OT_INT )
		InstantiateV(op_types);
	}

void ZAM_ExprOpTemplate::InstantiateC1(const vector<ZAM_OperandType>& ots,
                                       int arity, bool do_vec)
	{
	string args = "lhs, r1->AsConstExpr()";

	if ( arity == 1 && ots[0] == ZAM_OT_RECORD_FIELD )
		args += ", rhs->AsFieldExpr()->Field()";

	else if ( arity > 1 )
		{
		args += ", ";

		if ( ots[2] == ZAM_OT_RECORD_FIELD )
			args += "rhs->AsFieldExpr()->Field()";
		else
			args += "r2->AsNameExpr()";
		}

	auto m = MethodName(ots);

	EmitTo(C1Def);

	EmitNoNL("case EXPR_" + cname + ":");

	if ( do_vec )
		DoVectorCase(m, args);
	else
		EmitUp("return " + m + "(" + args + ");");

	if ( IncludesFieldOp() )
		{
		EmitTo(C1FieldDef);
		Emit("case EXPR_" + cname + ":\treturn " + m +
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
	Emit("case EXPR_" + cname + ":\treturn " + m + "(" + args + ");");

	if ( IncludesFieldOp() )
		{
		EmitTo(C2FieldDef);
		Emit("case EXPR_" + cname + ":\treturn " +
		     m + "_field(" + args + ", field);");
		}
	}

void ZAM_ExprOpTemplate::InstantiateC3(const vector<ZAM_OperandType>& ots)
	{
	EmitTo(C3Def);
	Emit("case EXPR_" + cname + ":\treturn " + MethodName(ots) +
	     "(lhs, r1->AsNameExpr(), r2->AsNameExpr(), r3->AsConstExpr());");
	}

void ZAM_ExprOpTemplate::InstantiateV(const vector<ZAM_OperandType>& ots)
	{
	auto m = MethodName(ots);

	string args = "lhs, r1->AsNameExpr()";

	if ( ots.size() >= 3 )
		{
		if ( ots[2] == ZAM_OT_INT )
			{
			string acc_flav = IncludesFieldOp() ? "Has" : "";
			args += ", rhs->As" + acc_flav + "FieldExpr()->Field()";
			}
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
		EmitUp("return " + m + "(" + args + ");");

	if ( IncludesFieldOp() )
		{
		EmitTo(VFieldDef);
		Emit("case EXPR_" + cname + ":\treturn " + m + "_field(" +
		     args + ", field);");
		}
	}

void ZAM_ExprOpTemplate::DoVectorCase(const string& m, const string& args)
	{
	NL();
	IndentUp();
	Emit("if ( rt->Tag() == TYPE_VECTOR )");
	EmitUp("return " + m + "_vec(" + args + ");");
	Emit("else");
	EmitUp("return " + m + "(" + args + ");");
	IndentDown();
	}

void ZAM_ExprOpTemplate::BuildInstructionCore(const string& params,
                                              const string& suffix,
	                                      ZAM_InstClass zc)
	{
	Emit("auto tag = t->Tag();");
	Emit("auto i_t = t->InternalType();");

	int ncases = 0;

	for ( auto& [et1, et2_map] : eval_mixed_set )
		for ( auto& [et2, eval] : et2_map )
			GenMethodTest(et1, et2, params, suffix,
			              ++ncases > 1, zc);

	bool do_default = false;

	for ( auto et : ExprTypes() )
		{
		if ( et == ZAM_EXPR_TYPE_DEFAULT )
			do_default = true;
		else
			GenMethodTest(et, et, params, suffix, ++ncases > 1, zc);
		}

	Emit("else");

	if ( do_default )
		{
		auto op = g->GenOpCode(this, suffix, zc);
		EmitUp("z = GenInst(" + op + ", " + params + ");");
		}

	else
		EmitUp("reporter->InternalError(\"bad tag when generating method core\");");
	}

void ZAM_ExprOpTemplate::GenMethodTest(ZAM_ExprType et1, ZAM_ExprType et2,
                                       const string& params,
                                       const string& suffix, bool do_else,
	                               ZAM_InstClass zc)
	{
	// Maps ZAM_ExprType's to the information needed (variable name,
	// constant to compare it against) to identify using an "if" test
	// that a given AST Expr node employs the given type of operand.
	static map<ZAM_ExprType, pair<string, string>> if_tests = {
		{ ZAM_EXPR_TYPE_ADDR, { "i_t", "TYPE_INTERNAL_ADDR" } },
		{ ZAM_EXPR_TYPE_ANY, { "tag", "TYPE_ANY" } },
		{ ZAM_EXPR_TYPE_DOUBLE, { "i_t", "TYPE_INTERNAL_DOUBLE" } },
		{ ZAM_EXPR_TYPE_FILE, { "tag", "TYPE_FILE" } },
		{ ZAM_EXPR_TYPE_FUNC, { "tag", "TYPE_FUNC" } },
		{ ZAM_EXPR_TYPE_INT, { "i_t", "TYPE_INTERNAL_INT" } },
		{ ZAM_EXPR_TYPE_LIST, { "tag", "TYPE_LIST" } },
		{ ZAM_EXPR_TYPE_OPAQUE, { "tag", "TYPE_OPAQUE" } },
		{ ZAM_EXPR_TYPE_PATTERN, { "tag", "TYPE_PATTERN" } },
		{ ZAM_EXPR_TYPE_RECORD, { "tag", "TYPE_RECORD" } },
		{ ZAM_EXPR_TYPE_STRING, { "i_t", "TYPE_INTERNAL_STRING" } },
		{ ZAM_EXPR_TYPE_SUBNET, { "i_t", "TYPE_INTERNAL_SUBNET" } },
		{ ZAM_EXPR_TYPE_TABLE, { "tag", "TYPE_TABLE" } },
		{ ZAM_EXPR_TYPE_TYPE, { "tag", "TYPE_TYPE" } },
		{ ZAM_EXPR_TYPE_UINT, { "i_t", "TYPE_INTERNAL_UNSIGNED" } },
		{ ZAM_EXPR_TYPE_VECTOR, { "tag", "TYPE_VECTOR" } },
	};

	if ( if_tests.count(et1) == 0 )
		g->Gripe("bad op-type", op_loc);

	auto if_test = if_tests[et1];
	auto if_var = if_test.first;
	auto if_val = if_test.second;

	string test = "if ( " + if_var + " == " + if_val + " )";
	if ( do_else )
		test = "else " + test;

	Emit(test);

	auto op_suffix = suffix + "_" + expr_name_types[et1];
	if ( et2 != et1 )
		op_suffix += expr_name_types[et2];

	auto op = g->GenOpCode(this, op_suffix, zc);
	EmitUp("z = GenInst(" + op + ", " + params + ");");
	}


EvalInstance::EvalInstance(ZAM_ExprType _lhs_et, ZAM_ExprType _op1_et,
         	           ZAM_ExprType _op2_et, string _eval, bool _is_def)
	{
	lhs_et = _lhs_et;
	op1_et = _op1_et;
	op2_et = _op2_et;
	eval = move(_eval);
	is_def = _is_def;
	}

string EvalInstance::LHSAccessor(bool is_ptr) const
	{
	if ( lhs_et == ZAM_EXPR_TYPE_NONE || lhs_et == ZAM_EXPR_TYPE_DEFAULT)
		return "";

	string deref = is_ptr ? "->" : ".";
	string acc = find_type_accessor(lhs_et);

	return deref + acc;
	}

string EvalInstance::Accessor(ZAM_ExprType et, bool is_ptr) const
	{
	if ( et == ZAM_EXPR_TYPE_NONE ||
	     et == ZAM_EXPR_TYPE_DEFAULT)
		return "";

	string deref = is_ptr ? "->" : ".";
	return deref + "As" + find_type_info(et).accessor + "()";
	}

string EvalInstance::OpMarker() const
	{
	if ( op1_et == ZAM_EXPR_TYPE_DEFAULT || op1_et == ZAM_EXPR_TYPE_NONE )
		return "";

	if ( op1_et == op2_et )
		return "_" + find_type_info(op1_et).suffix;

	return "_" + find_type_info(op1_et).suffix +
	       find_type_info(op2_et).suffix;
	}


void ZAM_ExprOpTemplate::InstantiateEval(const vector<ZAM_OperandType>& ot_orig,
                                         const string& suffix, ZAM_InstClass zc)
	{
	if ( expr_types.empty() )
		{ // No operand types to expand over.
		ZAM_OpTemplate::InstantiateEval(ot_orig, suffix, zc);
		return;
		}

	auto ot = ot_orig;
	if ( zc == ZIC_FIELD )
		// Make room for the offset.
		ot.emplace_back(ZAM_OT_INT);

	auto ot_str = OpSuffix(ot);

	// Some of these might not wind up being used, but no harm in
	// initializing them in case they are.
	string lhs, op1, op2;
	string branch_target = "z.v";

	EmitTarget emit_target = Eval;

	if ( zc == ZIC_VEC )
		{
		lhs = "vec1[i]";
		op1 = "vec2[i]";
		op2 = "vec3[i]";

		emit_target = Arity() == 1 ? Vec1Eval : Vec2Eval;
		}

	else
		{
		lhs = "frame[z.v1]";

		auto op1_offset = zc == ZIC_COND ? 1 : 2;
		auto op2_offset = op1_offset + 1;
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
			op1 = "frame[z.v" + to_string(op1_offset) + "]";

			if ( Arity() > 1 && ot[2] == ZAM_OT_VAR )
				branch_target += "3";
			else
				branch_target += "2";
			}

		if ( ot2_const )
			op2 = "z.c";
		else
			op2 = "frame[z.v" + to_string(op2_offset) + "]";

		if ( zc == ZIC_FIELD )
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

			lhs += ".AsRecord()->RawField(z.v" + to_string(f) + ")";
			}
		}

	vector<EvalInstance> eval_instances;

	for ( auto et : expr_types )
		{
		auto is_def = eval_set.count(et) == 0;
		string eval = is_def ? GetEval() : eval_set[et];
		auto lhs_et = IsConditionalOp() ? ZAM_EXPR_TYPE_INT : et;
		eval_instances.emplace_back(lhs_et, et, et, eval, is_def);
		}

	if ( zc != ZIC_VEC )
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
				eval_instances.emplace_back(lhs_et, et1, et2,
							    em2.second, false);
				}
			}

	for ( auto& ei : eval_instances )
		{
		auto lhs_accessor = ei.LHSAccessor();
		if ( HasExplicitResultType() )
			lhs_accessor = "";

		string lhs_ei = lhs;
		if ( zc != ZIC_VEC )
			lhs_ei += lhs_accessor;

		auto op1_ei = op1 + ei.Op1Accessor(zc == ZIC_VEC);
		auto op2_ei = op2 + ei.Op2Accessor(zc == ZIC_VEC);

		auto eval = SkipWS(ei.Eval());

		auto has_target = eval.find("$$") != string::npos;

		if ( zc == ZIC_VEC )
			{
			const char* rhs;
			if ( has_target )
				rhs = "\\$\\$ = ([^;\n]*)";
			else
				rhs = "^[^;\n]*";

			auto replacement = VecEvalRE(has_target);

			eval = regex_replace(eval, regex(rhs), replacement);
			}

		auto is_none = ei.LHS_ET() == ZAM_EXPR_TYPE_NONE;
		auto is_default = ei.LHS_ET() == ZAM_EXPR_TYPE_DEFAULT;

		if ( zc != ZIC_FIELD && ! is_none && ! is_default &&
		     find_type_info(ei.LHS_ET()).is_managed &&
		     ! HasExplicitResultType() )
			{
			auto delim = zc == ZIC_VEC ? "->" : ".";
			auto pre = "auto hold_lhs = " + lhs + delim +
			           "ManagedVal();\n\t";
			auto post = "\tUnref(hold_lhs);";
			eval = pre + eval + post;
			}

		eval = regex_replace(eval, regex("\\$1"), op1_ei);
		eval = regex_replace(eval, regex("\\$2"), op2_ei);

		string pre = GetPreEval();
		pre = regex_replace(pre, regex("\\$1"), op1_ei);
		pre = regex_replace(pre, regex("\\$2"), op2_ei);

		if ( has_target )
			eval = regex_replace(eval, regex("\\$\\$"), lhs_ei);

		else if ( zc == ZIC_COND )
			{ // Aesthetics: get rid of trailing newlines.
			eval = regex_replace(eval, regex("\n"), "");
			eval = "if ( ! (" + eval + ") ) " +
			       "{ pc = " + branch_target + "; continue; }";
			}

		else if ( ! is_none && (ei.IsDefault() || IsConditionalOp()) )
			{
			eval = lhs_ei + " = " + eval;

			// Ensure a single terminating semicolon.
			eval = regex_replace(eval, regex(";*\n"), ";\n");
			}

		eval = pre + eval;

		auto full_suffix = ot_str + suffix + ei.OpMarker();

		ZAM_OpTemplate::InstantiateEval(emit_target, full_suffix,
		                                eval, zc);

		if ( zc == ZIC_VEC )
			{
			string dispatch_params = "frame[z.v1].AsVectorRef(), frame[z.v2].AsVector()";

			if ( Arity() == 2 )
				dispatch_params += ", frame[z.v3].AsVector()";

			auto op_code = g->GenOpCode(this, "_" + full_suffix);
			auto dispatch = "vec_exec(" + op_code + ", z.t, " +
					dispatch_params + ", z);";

			ZAM_OpTemplate::InstantiateEval(Eval, full_suffix,
							dispatch, zc);
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

void ZAM_UnaryExprOpTemplate::BuildInstruction(const vector<ZAM_OperandType>& ot,
                                               const string& params,
					       const string& suffix,
                                               ZAM_InstClass zc)
	{
	const auto& ets = ExprTypes();

	if ( ets.size() == 1 && ets.count(ZAM_EXPR_TYPE_NONE) == 1 )
		{
		ZAM_ExprOpTemplate::BuildInstruction(ot, params, suffix, zc);
		return;
		}

	auto constant_op = ot[1] == ZAM_OT_CONSTANT;
	string type_src = constant_op ? "c" : "n2";

	if ( ot[0] == ZAM_OT_ASSIGN_FIELD )
		{
		type_src = constant_op ? "n" : "n1";
		Emit("auto " + type_src + " = flhs->GetOp1()->AsNameExpr();");
		Emit("auto t = flhs->GetType();");
		Emit("int field = flhs->Field();");
		}

	else
		{
		if ( IsAssignOp() )
			type_src = constant_op ? "n" : "n1";

		auto type_suffix = zc == ZIC_VEC ? "->Yield();" : ";";
		Emit("auto t = " + type_src + "->GetType()" + type_suffix);
		}

	BuildInstructionCore(params, suffix, zc);

	if ( IsAssignOp() && IsFieldOp() )
		// These can't take the type from the LHS variable, since
		// that's the enclosing record and not the field within it.
		Emit("z.t = t;");

	else if ( zc == ZIC_VEC )
		{
		if ( constant_op )
			Emit("z.t = n->GetType();");
		else
			Emit("z.t = n1->GetType();");
		}
	}


ZAM_AssignOpTemplate::ZAM_AssignOpTemplate(ZAMGen* _g, string _base_name)
: ZAM_UnaryExprOpTemplate(_g, _base_name)
	{
	// Assignments apply to every valid form of ExprType.
	for ( auto& etn : expr_type_names )
		{
		auto et = etn.second;
		if ( et != ZAM_EXPR_TYPE_NONE && et != ZAM_EXPR_TYPE_DEFAULT )
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

	if ( ots[0] == ZAM_OT_RECORD_FIELD )
		ots.push_back(ZAM_OT_INT);

	InstantiateOp(ots, false);
	if ( IsFieldOp() )
		InstantiateC1(ots, 1);

	ots[1] = ZAM_OT_VAR;
	InstantiateOp(ots, false);

	// ... and for assignments to fields, additional field versions.
	if ( ots[0] == ZAM_OT_ASSIGN_FIELD )
		{
		ots.push_back(ZAM_OT_INT);
		InstantiateOp(ots, false);

		ots[1] = ZAM_OT_CONSTANT;
		InstantiateOp(ots, false);
		}

	else if ( IsFieldOp() )
		InstantiateV(ots);
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

void ZAM_BinaryExprOpTemplate::BuildInstruction(const vector<ZAM_OperandType>& ot,
                                                const string& params,
					        const string& suffix,
                                                ZAM_InstClass zc)
	{
	auto constant_op = ot[1] == ZAM_OT_CONSTANT;
	string type_src = constant_op ? "c" : "n2";
	auto type_suffix = zc == ZIC_VEC ? "->Yield();" : ";";
	Emit("auto t = " + type_src + "->GetType()" + type_suffix);
	BuildInstructionCore(params, suffix, zc);

	if ( zc == ZIC_VEC )
		Emit("z.t = n1->GetType();");
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

void ZAM_RelationalExprOpTemplate::BuildInstruction(const vector<ZAM_OperandType>& ot,
                                                    const string& params,
                                                    const string& suffix,
						    ZAM_InstClass zc)
	{
	string op1;

	if ( zc == ZIC_COND )
		{
		if ( ot[1] == ZAM_OT_CONSTANT )
			op1 = "c";
		else if ( ot[2] == ZAM_OT_CONSTANT )
			op1 = "n";
		else
			op1 = "n1";
		}
	else
		op1 = "n2";

	auto type_suffix = zc == ZIC_VEC ? "->Yield();" : ";";
	Emit("auto t = " + op1 + "->GetType()" + type_suffix);
	BuildInstructionCore(params, suffix, zc);

	if ( zc == ZIC_VEC )
		Emit("z.t = n1->GetType();");
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

void ZAM_InternalBinaryOpTemplate::InstantiateEval(const vector<ZAM_OperandType>& ot,
                                                   const string& suffix,
                                                   ZAM_InstClass zc)
	{
	assert(ot.size() == 3);

	auto op1_const = ot[1] == ZAM_OT_CONSTANT;
	auto op2_const = ot[2] == ZAM_OT_CONSTANT;

	string op1 = op1_const ? "z.c" : "frame[z.v2]";
	string op2 = op2_const ? "z.c" :
	                         (op1_const ? "frame[z.v2]" : "frame[z.v3]");

	string prelude = "auto op1 = " + op1 + "." + op1_accessor + ";\n";
	prelude += "auto op2 = " + op2 + "." + op2_accessor + ";\n";

	auto eval = prelude + GetEval();

	auto& ets = ExprTypes();
	if ( ! ets.empty() )
		{
		if ( ets.size() != 1 )
			g->Gripe("internal-binary-op's can have at most one op-type", op_loc);

		for ( auto& et : ets )
			{
			auto acc = find_type_accessor(et);
			auto lhs = "frame[z.v1]." + acc;
			eval = regex_replace(eval, regex("\\$\\$"), lhs);
			}
		}

	ZAM_OpTemplate::InstantiateEval(Eval, OpSuffix(ot) + suffix, eval, zc);
	}


void ZAM_InternalOpTemplate::Parse(const string& attr, const string& line,
                                   const Words& words)
	{
	if ( attr != "num-call-args" )
		{
		if ( attr == "indirect-call" )
			{
			if ( words.size() != 1 )
				g->Gripe("indirect-call takes one argument", line);
			// Note, currently only works with a *subsequent*
			// num-call-args, whose setting needs to be 'n'.
			is_indirect_call = true;
			}
		else
			ZAM_OpTemplate::Parse(attr, line, words);

		return;
		}

	if ( words.size() != 2 )
		g->Gripe("num-call-args takes one argument", line);

	eval = "std::vector<ValPtr> args;\n";

	auto& arg = words[1];
	int n = arg == "n" ? -1 : stoi(arg);

	auto arg_offset = HasAssignVal() ? 1 : 0;
	auto arg_slot = arg_offset + 1;

	string func = "z.func";

	if ( n == 1 )
		{
		eval += "args.push_back(";
		if ( op_types[arg_offset] == ZAM_OT_CONSTANT )
			eval += "z.c";
		else
			eval += "frame[z.v" + to_string(arg_slot) + "]";

		eval += ".ToVal(z.t));\n";
		}

	else if ( n != 0 )
		{
		eval += "auto aux = z.aux;\n";

		if ( n < 0 )
			{
			if ( is_indirect_call )
				{
				func = "func";

				eval += "auto sel = z.v" + to_string(arg_slot) +
				        ";\n";
				eval += "auto func = (sel < 0) ? ";
				eval += "aux->id_val->GetVal()->AsFunc() : ";
				eval += "frame[sel].AsFunc();\n";
				}

			eval += "auto n = aux->n;\n";
			eval += "for ( auto i = 0; i < n; ++i )\n";
			eval += "\targs.push_back(aux->ToVal(frame, i));\n";
			}

		else
			for ( auto i = 0; i < n; ++i )
				{
				eval += "args.push_back(aux->ToVal(frame, ";
				eval += to_string(i);
				eval += "));\n";
				}
		}

	eval += "f->SetCallLoc(z.loc);\n";

	if ( HasAssignVal() )
		{
		auto av = GetAssignVal();
		eval += "auto " + av + " = " +
		        func + "->Invoke(&args, f);\n";
		eval += "if ( ! " + av + " ) { ZAM_error = true; break; }\n";
		}
	else
		eval += "(void) " + func + "->Invoke(&args, f);\n";
	}


bool TemplateInput::ScanLine(string& line)
	{
	if ( ! put_back.empty() )
		{
		line = put_back;
		put_back.clear();
		return true;
		}

	char buf[8192];

	// Read lines, discarding comments, which have to start at the
	// beginning of a line.
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

void TemplateInput::Gripe(const char* msg, const string& input) const
	{
	auto input_s = input.c_str();
	int n = strlen(input_s);

	fprintf(stderr, "%s, line %d: %s - %s",
	        loc.file_name, loc.line_num, msg, input_s);
	if ( n == 0 || input_s[n-1] != '\n' )
		fprintf(stderr, "\n");

	exit(1);
	}

void TemplateInput::Gripe(const char* msg, const InputLoc& l) const
	{
	fprintf(stderr, "%s, line %d: %s\n", l.file_name, l.line_num, msg);
	exit(1);
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

	InitEmitTargets();

	while ( ParseTemplate() )
		;

	for ( auto& t : templates )
		t->Instantiate();

	GenMacros();

	CloseEmitTargets();
	}

void ZAMGen::ReadMacro(const string& line)
	{
	vector<string> mac;
	mac.emplace_back(SkipWords(line, 1));

	string s;
	while ( ScanLine(s) )
		{
		if ( s.size() <= 1 || ! isspace(s.c_str()[0]) )
			{
			PutBack(s);
			break;
			}

		mac.push_back(s);
		}

	macros.emplace_back(move(mac));
	}

void ZAMGen::GenMacros()
	{
	for ( auto& m : macros )
		{
		for ( auto i = 0U; i < m.size(); ++i )
			{
			auto ms = m[i];
			if ( i == 0 )
				ms = "#define " + ms;

			if ( i < m.size() - 1 )
				ms = regex_replace(ms, regex("\n"), " \\\n");

			Emit(EvalMacros, ms);
			}

		Emit(EvalMacros, "\n");
		}
	}

string ZAMGen::GenOpCode(const ZAM_OpTemplate* ot, const string& suffix,
                         ZAM_InstClass zc)
	{
	auto op = "OP_" + ot->CanonicalName() + suffix;

	static unordered_set<string> known_opcodes;

	if ( known_opcodes.count(op) > 0 )
		// We've already done this one, don't re-define its auxiliary
		// information.
		return op;

	known_opcodes.insert(op);

	IndentUp();

	// Generate the enum defining the opcode ...
	Emit(OpDef, op + ",");

	// ... the "flavor" of how it treats its first operand ...
	auto op_comment = ",\t// " + op;
	auto op1_always_read = (zc == ZIC_FIELD || zc == ZIC_COND);
	auto flavor = op1_always_read ? "OP1_READ" : ot->GetOp1Flavor();
	Emit(Op1Flavor, flavor + op_comment);

	// ... whether it has side effects ...
	auto se = ot->HasSideEffects() ? "true" : "false";
	Emit(OpSideEffects, se + op_comment);

	// ... and the switch case that maps the enum to a string
	// representation.
	auto name = ot->BaseName();
	transform(name.begin(), name.end(), name.begin(), ::tolower);
	name += suffix;
	transform(name.begin(), name.end(), name.begin(), under_to_dash);
	Emit(OpName, "case " + op + ":\treturn \"" + name + "\";");

	IndentDown();

	return op;
	}

void ZAMGen::Emit(EmitTarget et, const string& s)
	{
	assert(et != None);

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

void ZAMGen::InitEmitTargets()
	{
	// Maps an EmitTarget enum to its corresponding filename.
	static const unordered_map<EmitTarget, const char*> gen_file_names = {
		{ None, nullptr },
		{ AssignFlavor, "ZAM-AssignFlavorsDefs.h" },
		{ C1Def, "ZAM-GenExprsDefsC1.h" },
		{ C1FieldDef, "ZAM-GenFieldsDefsC1.h" },
		{ C2Def, "ZAM-GenExprsDefsC2.h" },
		{ C2FieldDef, "ZAM-GenFieldsDefsC2.h" },
		{ C3Def, "ZAM-GenExprsDefsC3.h" },
		{ Cond, "ZAM-Conds.h" },
		{ DirectDef, "ZAM-DirectDefs.h" },
		{ Eval, "ZAM-EvalDefs.h" },
		{ EvalMacros, "ZAM-EvalMacros.h" },
		{ MethodDecl, "ZAM-MethodDecls.h" },
		{ MethodDef, "ZAM-MethodDefs.h" },
		{ Op1Flavor, "ZAM-Op1FlavorsDefs.h" },
		{ OpDef, "ZAM-OpsDefs.h" },
		{ OpName, "ZAM-OpsNamesDefs.h" },
		{ OpSideEffects, "ZAM-OpSideEffects.h" },
		{ VDef, "ZAM-GenExprsDefsV.h" },
		{ VFieldDef, "ZAM-GenFieldsDefsV.h" },
		{ Vec1Eval, "ZAM-Vec1EvalDefs.h" },
		{ Vec2Eval, "ZAM-Vec2EvalDefs.h" },
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

	InitSwitch(C1Def, "C1 assignment");
	InitSwitch(C2Def, "C2 assignment");
	InitSwitch(C3Def, "C3 assignment");
	InitSwitch(VDef, "V assignment");

	InitSwitch(C1FieldDef, "C1 field assignment");
	InitSwitch(C2FieldDef, "C2 field assignment");
	InitSwitch(VFieldDef, "V field assignment");
	}

void ZAMGen::InitSwitch(EmitTarget et, string desc)
	{
	Emit(et, "{");
        Emit(et, "switch ( rhs->Tag() ) {");

	switch_targets[et] = desc;
	}

void ZAMGen::CloseEmitTargets()
	{
	FinishSwitches();

	for ( auto& gf : gen_files )
		fclose(gf.second);
	}

void ZAMGen::FinishSwitches()
	{
	for ( auto& st : switch_targets )
		{
		auto et = st.first;
		auto& desc = st.second;

		Emit(et, "default:");
		IndentUp();
		Emit(et, "reporter->InternalError(\"inconsistency in " + desc +
			 ": %s\", obj_desc(rhs).c_str());");
		IndentDown();
		Emit(et, "}");
		Emit(et, "}");
		}
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

	if ( op == "macro" )
		{
		ReadMacro(line);
		return true;
		}

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
	else if ( op == "direct-unary-op" && ! args_mismatch )
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


int main(int argc, char** argv)
	{
	ZAMGen(argc, argv);
	exit(0);
	}
