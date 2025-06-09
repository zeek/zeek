// See the file "COPYING" in the toplevel directory for copyright.

#include "Gen-ZAM.h"

#include <cstring>
#include <ctype.h>
#include <regex>

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
struct TypeInfo
	{
	string tag;
	ZAM_Type zt;
	string suffix;
	string accessor; // doesn't include "As" prefix or "()" suffix
	bool is_managed;
	};

static vector<TypeInfo> ZAM_type_info = {
	{"TYPE_ADDR", ZAM_TYPE_ADDR, "A", "Addr", true},
	{"TYPE_ANY", ZAM_TYPE_ANY, "a", "Any", true},
	{"TYPE_COUNT", ZAM_TYPE_UINT, "U", "Count", false},
	{"TYPE_DOUBLE", ZAM_TYPE_DOUBLE, "D", "Double", false},
	{"TYPE_FILE", ZAM_TYPE_FILE, "f", "File", true},
	{"TYPE_FUNC", ZAM_TYPE_FUNC, "F", "Func", true},
	{"TYPE_INT", ZAM_TYPE_INT, "I", "Int", false},
	{"TYPE_LIST", ZAM_TYPE_LIST, "L", "List", true},
	{"TYPE_OPAQUE", ZAM_TYPE_OPAQUE, "O", "Opaque", true},
	{"TYPE_PATTERN", ZAM_TYPE_PATTERN, "P", "Pattern", true},
	{"TYPE_RECORD", ZAM_TYPE_RECORD, "R", "Record", true},
	{"TYPE_STRING", ZAM_TYPE_STRING, "S", "String", true},
	{"TYPE_SUBNET", ZAM_TYPE_SUBNET, "N", "SubNet", true},
	{"TYPE_TABLE", ZAM_TYPE_TABLE, "T", "Table", true},
	{"TYPE_TYPE", ZAM_TYPE_TYPE, "t", "Type", true},
	{"TYPE_VECTOR", ZAM_TYPE_VECTOR, "V", "Vector", true},
};

// Maps op-type mnemonics to the corresponding internal value used by Gen-ZAM.
static unordered_map<char, ZAM_Type> type_names = {
	{'*', ZAM_TYPE_DEFAULT}, {'A', ZAM_TYPE_ADDR},    {'a', ZAM_TYPE_ANY},
	{'D', ZAM_TYPE_DOUBLE},  {'f', ZAM_TYPE_FILE},    {'F', ZAM_TYPE_FUNC},
	{'I', ZAM_TYPE_INT},     {'L', ZAM_TYPE_LIST},    {'X', ZAM_TYPE_NONE},
	{'O', ZAM_TYPE_OPAQUE},  {'P', ZAM_TYPE_PATTERN}, {'R', ZAM_TYPE_RECORD},
	{'S', ZAM_TYPE_STRING},  {'N', ZAM_TYPE_SUBNET},  {'T', ZAM_TYPE_TABLE},
	{'t', ZAM_TYPE_TYPE},    {'U', ZAM_TYPE_UINT},    {'V', ZAM_TYPE_VECTOR},
};

// Inverse of the above.
static unordered_map<ZAM_Type, char> expr_name_types;

// Given a ZAM_Type, returns the corresponding TypeInfo.
const TypeInfo& find_type_info(ZAM_Type zt)
	{
	assert(zt != ZAM_TYPE_NONE);

	auto pred = [zt](const TypeInfo& ti) -> bool
	{
		return ti.zt == zt;
	};
	auto ti = std::find_if(ZAM_type_info.begin(), ZAM_type_info.end(), pred);

	assert(ti != ZAM_type_info.end());
	return *ti;
	}

// Given a ZAM_Type, return its ZVal accessor.  Takes into account
// some naming inconsistencies between ZVal's and Val's.
string find_type_accessor(ZAM_Type zt, bool is_lhs)
	{
	if ( zt == ZAM_TYPE_NONE )
		return "";

	string acc = string("As") + find_type_info(zt).accessor;
	if ( is_lhs )
		acc += "Ref";

	return acc + "()";
	}

// Maps ZAM operand types to pairs of (1) the C++ name used to declare
// the operand in a method declaration, and (2) the variable name to
// use for the operand.
unordered_map<ZAM_OperandClass, pair<const char*, const char*>> ArgsManager::oc_to_args = {
	{ZAM_OC_AUX, {"OpaqueVals*", "v"}},
	{ZAM_OC_CONSTANT, {"const ConstExpr*", "c"}},
	{ZAM_OC_EVENT_HANDLER, {"EventHandler*", "h"}},
	{ZAM_OC_INT, {"int", "i"}},
	{ZAM_OC_BRANCH, {"int", "i"}},
	{ZAM_OC_GLOBAL, {"int", "i"}},
	{ZAM_OC_STEP_ITER, {"int", "i"}},
	{ZAM_OC_TBL_ITER, {"int", "i"}},
	{ZAM_OC_LIST, {"const ListExpr*", "l"}},
	{ZAM_OC_RECORD_FIELD, {"const NameExpr*", "n"}},
	{ZAM_OC_VAR, {"const NameExpr*", "n"}},

	// The following gets special treatment.
	{ZAM_OC_ASSIGN_FIELD, {"const NameExpr*", "n"}},
};

// The different operand classes that are represented as "raw" integers
// (meaning the slot value is used directly, rather than indexing the frame).
static const set<ZAM_OperandClass> raw_int_oc(
	{ ZAM_OC_BRANCH, ZAM_OC_GLOBAL, ZAM_OC_INT, ZAM_OC_STEP_ITER, ZAM_OC_TBL_ITER }
);

ArgsManager::ArgsManager(const OCVec& oc_orig, ZAM_InstClass zc)
	{
	auto oc = oc_orig;
	if ( zc == ZIC_COND )
		// Remove the final entry corresponding to the branch, as
		// we'll automatically generate it subsequently.
		oc.pop_back();

	int n = 0;
	bool add_field = false;

	for ( const auto& ot_i : oc )
		{
		if ( ot_i == ZAM_OC_NONE )
			{ // it had better be the only operand type
			assert(oc.size() == 1);
			break;
			}

		++n;

		// Start off the argument info using the usual case
		// of (1) same method parameter name as GenInst argument,
		// and (2) not requiring a record field.
		auto& arg_i = oc_to_args[ot_i];
		Arg arg = {arg_i.second, arg_i.first, arg_i.second};

		if ( ot_i == ZAM_OC_ASSIGN_FIELD )
			{
			if ( n == 1 )
				{ // special-case the parameter
				arg.decl_name = "flhs";
				arg.decl_type = "const FieldLHSAssignExpr*";
				}
			}

		args.emplace_back(std::move(arg));
		}

	Differentiate();
	}

void ArgsManager::Differentiate()
	{
	// First, figure out which parameter names are used how often.
	map<string, int> name_count; // how often the name apepars
	map<string, int> usage_count; // how often the name's been used so far
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
			continue; // it's unique

		auto n = to_string(++usage_count[name]);
		name += n;
		if ( decl_and_arg_same )
			decl += n;
		}

	// Finally, build the full versions of the declaration and parameters.

	for ( auto& arg : args )
		{
		if ( ! full_decl.empty() )
			full_decl += ", ";

		full_decl += arg.decl_type + " " + arg.decl_name;

		if ( ! full_params.empty() )
			full_params += ", ";

		full_params += arg.param_name;
		params.push_back(arg.param_name);
		}
	}

ZAM_OpTemplate::ZAM_OpTemplate(ZAMGen* _g, string _base_name) : g(_g), base_name(std::move(_base_name))
	{
	// Make the base name viable in a C++ name.
	transform(base_name.begin(), base_name.end(), base_name.begin(), dash_to_under);

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

	if ( ! op_classes.empty() && ! op_classes_vec.empty() )
		Gripe("\"class\" and \"classes\" are mutually exclusive");

	if ( ! op_classes.empty() || ! op_classes_vec.empty() )
		{
		auto nclasses = op_classes.empty() ?
				op_classes_vec[0].size() : op_classes.size();

		for ( auto& oc : op_classes_vec )
			if ( oc.size() != nclasses )
				Gripe("size mismatch in \"classes\" specifications");

		if ( ! op_types.empty() && op_types.size() != nclasses )
			Gripe("number of \"op-types\" elements must match \"class\"/\"classes\"");
		}

	else if ( ! op_types.empty() )
		Gripe("\"op-types\" can only be used with \"class\"/\"classes\"");
	}

void ZAM_OpTemplate::Instantiate()
	{
	if ( IsPredicate() )
		InstantiatePredicate();

	else if ( op_classes_vec.empty() )
		InstantiateOp(OperandClasses(), IncludesVectorOp());

	else
		for ( auto& ocs : op_classes_vec )
			InstantiateOp(ocs, IncludesVectorOp());
	}

void ZAM_OpTemplate::InstantiatePredicate()
	{
	if ( ! op_classes_vec.empty() )
		Gripe("\"predicate\" cannot include \"classes\"");

	if ( op_classes.empty() )
		Gripe("\"predicate\" requires a \"class\"");

	if ( IncludesVectorOp() )
		Gripe("\"predicate\" cannot include \"vector\"");

	// Build 3 forms: an assignment to an int-value'd $$, a conditional
	// if the evaluation is true, and one if it is not.

	auto orig_eval = eval;
	// Remove trailing '\n' from eval.
	orig_eval.pop_back();

	auto orig_op_classes = op_classes;
	bool no_classes = orig_op_classes[0] == ZAM_OC_NONE;

	// Assignment form.
	op_classes.clear();
	op_classes.push_back(ZAM_OC_VAR);
	if ( ! no_classes )
		op_classes.insert(op_classes.end(), orig_op_classes.begin(), orig_op_classes.end());

	string target_accessor;

	if ( ! op_types.empty() )
		op_types.insert(op_types.begin(), ZAM_TYPE_INT);
	else
		target_accessor = ".AsIntRef()";

	eval = "$$" + target_accessor + " = " + orig_eval + ";";

	InstantiateOp(op_classes, false);

	// Conditional form - branch if not true.

	if ( ! op_types.empty() )
		{
		// Remove 'V' at the beginning from the assignment form,
		// and add a 'i' at the end for the branch.
		op_types.erase(op_types.begin());
		op_types.push_back(ZAM_TYPE_INT);
		}

	cname += "_COND";
	op1_flavor = "OP1_READ";
	if ( no_classes )
		op_classes.clear();
	else
		op_classes = orig_op_classes;

	op_classes.push_back(ZAM_OC_BRANCH);

	auto branch_pos = to_string(op_classes.size());
	auto suffix = " )\n\t\t$" + branch_pos;
	eval = "if ( ! (" + orig_eval + ")" + suffix;
	InstantiateOp(op_classes, false);

	// Now the form that branches if true.
	cname = "NOT_" + cname;
	eval = "if ( (" + orig_eval + ")" + suffix;
	InstantiateOp(op_classes, false);
	}

void ZAM_OpTemplate::UnaryInstantiate()
	{
	// First operand is always the frame slot to which this operation
	// assigns the result of the applying unary operator.
	OCVec ocs = {ZAM_OC_VAR};
	ocs.resize(2);

	// Now build versions for a constant operand (maybe not actually
	// needed due to constant folding, but sometimes that gets deferred
	// to run-time) ...
	if ( ! NoConst() )
		{
		ocs[1] = ZAM_OC_CONSTANT;
		InstantiateOp(ocs, IncludesVectorOp());
		}

	// ... and for a variable (frame-slot) operand.
	ocs[1] = ZAM_OC_VAR;
	InstantiateOp(ocs, IncludesVectorOp());
	}

void ZAM_OpTemplate::Parse(const string& attr, const string& line, const Words& words)
	{
	int num_args = -1; // -1 = don't enforce
	int nwords = static_cast<int>(words.size());

	if ( attr == "class" )
		{
		if ( nwords <= 1 )
			g->Gripe("missing argument", line);

		num_args = 1;
		op_classes = ParseClass(words[1]);
		}

	else if ( attr == "classes" )
		{
		if ( nwords <= 1 )
			g->Gripe("missing argument", line);

		num_args = -1;

		for ( int i = 1; i < nwords; ++i )
			op_classes_vec.push_back(ParseClass(words[i]));
		}

	else if ( attr == "op-types" )
		{
		if ( words.size() == 1 )
			g->Gripe("op-types needs arguments", line);

		for ( auto i = 1U; i < words.size(); ++i )
			{
			auto& w_i = words[i];
			if ( w_i.size() != 1 )
				g->Gripe("bad op-types argument", w_i);

			auto et_c = w_i.c_str()[0];
			if ( type_names.count(et_c) == 0 )
				g->Gripe("bad op-types argument", w_i);

			op_types.push_back(type_names[et_c]);
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

OCVec ZAM_OpTemplate::ParseClass(const string& spec) const
	{
	OCVec ocs;

	const char* types = spec.c_str();
	while ( *types )
		{
		ZAM_OperandClass oc = ZAM_OC_NONE;

		switch ( *types )
			{
			case 'C':
				oc = ZAM_OC_CONSTANT;
				break;
			case 'F':
				oc = ZAM_OC_ASSIGN_FIELD;
				break;
			case 'H':
				oc = ZAM_OC_EVENT_HANDLER;
				break;
			case 'L':
				oc = ZAM_OC_LIST;
				break;
			case 'O':
				oc = ZAM_OC_AUX;
				break;
			case 'R':
				oc = ZAM_OC_RECORD_FIELD;
				break;
			case 'V':
				oc = ZAM_OC_VAR;
				break;
			case 'i':
				oc = ZAM_OC_INT;
				break;
			case 'b':
				oc = ZAM_OC_BRANCH;
				break;
			case 'f': // 'f' = "for" loop
				oc = ZAM_OC_TBL_ITER;
				break;
			case 'g':
				oc = ZAM_OC_GLOBAL;
				break;
			case 's':
				oc = ZAM_OC_STEP_ITER;
				break;

			case 'X':
				oc = ZAM_OC_NONE;
				break;

			default:
				g->Gripe("bad operand type", spec);
				break;
			}

		ocs.push_back(oc);

		++types;
		}

	return ocs;
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
		return 0;

	if ( arg[0] != '$' )
		g->Gripe("bad set-type parameter, should be $n", arg);

	int param = atoi(&arg[1]);

	if ( param <= 0 || param > 2 )
		g->Gripe("bad set-type parameter, should be $1 or $2", arg);

	return param;
	}

// Maps an operand type to a character mnemonic used to distinguish
// it from others.
unordered_map<ZAM_OperandClass, char> ZAM_OpTemplate::oc_to_char = {
	{ZAM_OC_AUX, 'O'},
	{ZAM_OC_CONSTANT, 'C'},
	{ZAM_OC_EVENT_HANDLER, 'H'},
	{ZAM_OC_ASSIGN_FIELD, 'F'},
	{ZAM_OC_INT, 'i'},
	{ZAM_OC_LIST, 'L'},
	{ZAM_OC_NONE, 'X'},
	{ZAM_OC_RECORD_FIELD, 'R'},
	{ZAM_OC_VAR, 'V'},
	{ZAM_OC_BRANCH, 'b'},
	{ZAM_OC_GLOBAL, 'g'},
	{ZAM_OC_STEP_ITER, 's'},
	{ZAM_OC_TBL_ITER, 'f'},
};

void ZAM_OpTemplate::InstantiateOp(const OCVec& oc, bool do_vec)
	{
	auto method = MethodName(oc);

	InstantiateOp(method, oc, ZIC_REGULAR);

	if ( IncludesFieldOp() )
		InstantiateOp(method, oc, ZIC_FIELD);

	if ( do_vec )
		InstantiateOp(method, oc, ZIC_VEC);

	if ( IsConditionalOp() )
		InstantiateOp(method, oc, ZIC_COND);
	}

void ZAM_OpTemplate::InstantiateOp(const string& orig_method, const OCVec& oc_orig,
                                   ZAM_InstClass zc)
	{
	auto oc = oc_orig;
	string suffix = "";

	if ( zc == ZIC_FIELD )
		{
		// Make room for the offset.
		oc.push_back(ZAM_OC_INT);
		suffix = NoEval() ? "" : "_field";
		}

	else if ( zc == ZIC_COND )
		{
		// Remove the assignment and add in the branch.
		oc.erase(oc.begin());
		oc.push_back(ZAM_OC_BRANCH);
		suffix = "_cond";
		}

	else if ( zc == ZIC_VEC )
		{
		// Don't generate versions of these for constant operands
		// as those don't exist.
		if ( int(oc.size()) != Arity() + 1 )
			Gripe("vector class/arity mismatch");

		if ( oc[1] == ZAM_OC_CONSTANT )
			return;
		if ( Arity() > 1 && oc[2] == ZAM_OC_CONSTANT )
			return;

		suffix = "_vec";
		}

	auto method = MethodName(oc);

	if ( ! IsInternalOp() )
		InstantiateMethod(method, suffix, oc, zc);

	if ( IsAssignOp() )
		InstantiateAssignOp(oc, suffix);
	else
		{
		InstantiateEval(oc, suffix, zc);

		if ( HasAssignmentLess() )
			{
			auto op_string = "_" + OpSuffix(oc);
			auto op = g->GenOpCode(this, op_string);
			GenAssignmentlessVersion(op);
			}
		}
	}

void ZAM_OpTemplate::GenAssignmentlessVersion(const string& op)
	{
	EmitTo(AssignFlavor);
	Emit("assignmentless_op[" + op + "] = " + AssignmentLessOp() + ";");
	Emit("assignmentless_op_class[" + op + "] = " + AssignmentLessOpClass() + ";");
	}

void ZAM_OpTemplate::InstantiateMethod(const string& m, const string& suffix,
                                       const OCVec& oc, ZAM_InstClass zc)
	{
	if ( IsInternalOp() )
		return;

	auto decls = MethodDeclare(oc, zc);

	EmitTo(MethodDecl);
	Emit("const ZAMStmt " + m + suffix + "(" + decls + ");");

	EmitTo(MethodDef);
	Emit("const ZAMStmt ZAMCompiler::" + m + suffix + "(" + decls + ")");
	BeginBlock();

	InstantiateMethodCore(oc, suffix, zc);

	if ( HasPostMethod() )
		Emit(GetPostMethod());

	if ( ! HasCustomMethod() )
		Emit("return AddInst(z);");

	EndBlock();
	NL();
	}

void ZAM_OpTemplate::InstantiateMethodCore(const OCVec& oc, const string& suffix,
                                           ZAM_InstClass zc)
	{
	if ( HasCustomMethod() )
		{
		Emit(GetCustomMethod());
		return;
		}

	assert(! oc.empty());

	string full_suffix = "_" + OpSuffix(oc) + suffix;

	Emit("ZInstI z;");

	if ( oc[0] == ZAM_OC_AUX )
		{
		auto op = g->GenOpCode(this, full_suffix, zc);
		Emit("z = ZInstI(" + op + ");");
		return;
		}

	if ( oc[0] == ZAM_OC_NONE )
		{
		auto op = g->GenOpCode(this, full_suffix, zc);
		Emit("z = GenInst(" + op + ");");
		return;
		}

	if ( oc.size() > 1 && oc[1] == ZAM_OC_AUX )
		{
		auto op = g->GenOpCode(this, full_suffix, zc);
		Emit("z = ZInstI(" + op + ", Frame1Slot(n, " + op + "));");
		return;
		}

	ArgsManager args(oc, zc);
	BuildInstruction(oc, args.Params(), full_suffix, zc);

	auto& tp = GetTypeParam();
	if ( tp )
		Emit("z.SetType(" + args.NthParam(*tp) + "->GetType());");

	auto& tp2 = GetType2Param();
	if ( tp2 )
		Emit("z.SetType2(" + args.NthParam(*tp2) + "->GetType());");
	}

void ZAM_OpTemplate::BuildInstruction(const OCVec& oc, const string& params,
                                      const string& suffix, ZAM_InstClass zc)
	{
	auto op = g->GenOpCode(this, suffix, zc);
	Emit("z = GenInst(" + op + ", " + params + ");");
	}

static bool skippable_ot(ZAM_OperandClass oc)
	{
	return oc == ZAM_OC_EVENT_HANDLER || oc == ZAM_OC_AUX || oc == ZAM_OC_LIST;
	}

string ZAM_OpTemplate::ExpandParams(const OCVec& oc, string eval, const vector<string>& accessors) const
	{
	auto have_target = eval.find("$$") != string::npos;

	auto fl = GetOp1Flavor();
	auto need_target = fl == "OP1_WRITE";

	auto oc_size = oc.size();
	if ( oc_size > 0 )
		{
		auto oc0 = oc[0];

		if ( oc0 == ZAM_OC_NONE || oc0 == ZAM_OC_AUX )
			{
			--oc_size;
			need_target = false;
			}

		else if ( raw_int_oc.count(oc0) > 0 )
			need_target = false;
		}

	while ( oc_size > 0 && skippable_ot(oc[oc_size - 1]) )
		--oc_size;

	auto max_param = oc_size;

	if ( need_target && ! have_target )
		Gripe("eval missing $$:", eval);

	if ( have_target )
		{
		assert(max_param > 0);
		--max_param;
		}

	bool has_d1 = eval.find("$1") != string::npos;
	bool has_d2 = eval.find("$2") != string::npos;
	bool has_d3 = eval.find("$3") != string::npos;
	bool has_d4 = eval.find("$4") != string::npos;

	switch ( max_param ) {
	case 4: if ( ! has_d4 ) Gripe("eval missing $4", eval);
	case 3: if ( ! has_d3 ) Gripe("eval missing $3", eval);
	case 2: if ( ! has_d2 ) Gripe("eval missing $2", eval);
	case 1: if ( ! has_d1 ) Gripe("eval missing $1", eval);

	case 0:
		break;

	default:
		Gripe("unexpected param size", to_string(max_param) + " - " +  eval);
		break;
	}

	switch ( max_param ) {
	case 0: if ( has_d1 ) Gripe("extraneous $1 in eval", eval);
	case 1: if ( has_d2 ) Gripe("extraneous $2 in eval", eval);
	case 2: if ( has_d3 ) Gripe("extraneous $3 in eval", eval);
	case 3: if ( has_d4 ) Gripe("extraneous $4 in eval", eval);

	case 4:
		break;

	default:
		Gripe("unexpected param size", to_string(max_param) + " - " +  eval);
		break;
	}

	int frame_slot = 0;
	bool const_seen = false;
	bool int_seen = false;

	for ( size_t i = 0; i < oc_size; ++i )
		{
		string op;
		bool needs_accessor = true;

		switch ( oc[i] ) {
		case ZAM_OC_VAR:
			if ( int_seen )
				Gripe("'V' type specifier after 'i' specifier", eval);
			op = "frame[z.v" + to_string(++frame_slot) + "]";
			break;

		case ZAM_OC_RECORD_FIELD:
			op = "frame[z.v" + to_string(++frame_slot) + "]";
			break;

		case ZAM_OC_INT:
		case ZAM_OC_BRANCH:
		case ZAM_OC_GLOBAL:
		case ZAM_OC_STEP_ITER:
		case ZAM_OC_TBL_ITER:
			op = "z.v" + to_string(++frame_slot);
			int_seen = true;
			needs_accessor = false;

			if ( oc[i] == ZAM_OC_BRANCH )
				op = "Branch(" + op + ")";
			else if ( oc[i] == ZAM_OC_STEP_ITER )
				op = "StepIter(" + op + ")";
			else if ( oc[i] == ZAM_OC_TBL_ITER )
				op = "TableIter(" + op + ")";
			break;

		case ZAM_OC_CONSTANT:
			if ( const_seen )
				g->Gripe("double constant", eval.c_str());
			const_seen = true;
			op = "z.c";
			break;

		default:
			Gripe("unexpected oc type", eval);
			break;
		}

		if ( needs_accessor )
			{
			if ( ! accessors.empty() && ! accessors[i].empty() )
				op += "." + accessors[i];
			else if ( ! op_types.empty() && op_types[i] != ZAM_TYPE_NONE )
				op += "." + find_type_accessor(op_types[i], have_target && i == 0);
			}

		else if ( ! op_types.empty() && oc[i] == ZAM_OC_INT )
			{
			if ( op_types[i] == ZAM_TYPE_UINT )
				op = "zeek_uint_t(" + op + ")";
			}

		string pat;
		if ( i == 0 && have_target )
			pat = "\\$\\$";
		else
			pat = "\\$" + to_string(have_target ? i : i + 1);

		auto orig_eval = eval;
		eval = regex_replace(eval, regex(pat), op);
		if ( orig_eval == eval )
			Gripe("no eval sub", pat + " - " + eval);
		}

	return eval;
	}

void ZAM_OpTemplate::InstantiateEval(const OCVec& oc, const string& suffix,
                                     ZAM_InstClass zc)
	{
	if ( NoEval() )
		return;

	auto eval = ExpandParams(oc, GetEval(), accessors);

	GenEval(Eval, OpSuffix(oc), suffix, eval, zc);
	}

void ZAM_OpTemplate::GenEval(EmitTarget et, const string& oc_str, const string& op_suffix, const string& eval, ZAM_InstClass zc)
	{
	auto op_code = g->GenOpCode(this, "_" + oc_str + op_suffix, zc);

	if ( et == Eval )
		{
		auto oc_str_copy = oc_str;
		if ( zc == ZIC_COND )
			{
			auto n = oc_str_copy.size();

			if ( oc_str_copy[n-1] == 'V' )
				oc_str_copy[n-1] = 'i';

			else if ( oc_str_copy[n-1] == 'C' )
				{
				if ( oc_str_copy[n-2] != 'V' )
					Gripe("bad operator class");

				oc_str_copy[n-2] = 'C';
				oc_str_copy[n-1] = 'i';
				}
			}

		GenDesc(op_code, oc_str_copy, eval);
		}

	EmitTo(et);
	Emit("case " + op_code + ":");
	BeginBlock();
	Emit(eval);
	EndBlock();
	EmitUp("break;");
	NL();
	}

void ZAM_OpTemplate::GenDesc(const string& op_code, const string& oc_str, const string& eval)
	{
	StartDesc(op_code, oc_str);
	Emit(eval);
	EndDesc();
	}

void ZAM_OpTemplate::StartDesc(const string& op_code, const string& oc_str)
	{
	EmitTo(OpDesc);
	Emit("{ " + op_code + ",");
	BeginBlock();
	Emit("\"" + oc_str + "\",");

	if ( op_types.empty() )
		Emit("\"\",");
	else
		{
		string ots;
		for ( auto ot : op_types )
			{
			if ( ot == ZAM_TYPE_DEFAULT )
				ots += "X";
			else
				ots += expr_name_types[ot];
			}

		Emit("\"" + ots + "\", ");
		}

	StartString();
	}

void ZAM_OpTemplate::EndDesc()
	{
	EndString();
	EndBlock();
	Emit("},");
	}

void ZAM_OpTemplate::InstantiateAssignOp(const OCVec& oc, const string& suffix)
	{
	// First, create a generic version of the operand, which the
	// ZAM compiler uses to find specific-flavored versions.
	auto oc_str = OpSuffix(oc);
	auto op_string = "_" + oc_str;
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

		StartDesc(op, oc_str);
		GenAssignOpCore(oc, eval, ti.accessor, ti.is_managed);
		if ( ! post_eval.empty() )
			Emit(post_eval);
		EndDesc();

		EmitTo(Eval);
		Emit("case " + op + ":");
		BeginBlock();
		GenAssignOpCore(oc, eval, ti.accessor, ti.is_managed);
		if ( ! post_eval.empty() )
			Emit(post_eval);
		Emit("break;");
		EndBlock();
		}

	post_eval.clear();
	}

void ZAM_OpTemplate::GenAssignOpCore(const OCVec& oc, const string& eval,
                                     const string& accessor, bool is_managed)
	{
	if ( HasAssignVal() )
		{
		GenAssignOpValCore(oc, eval, accessor, is_managed);
		return;
		}

	if ( ! eval.empty() )
		g->Gripe("assign-op should not have an \"eval\"", eval);

	auto lhs_field = (oc[0] == ZAM_OC_ASSIGN_FIELD);
	auto rhs_field = lhs_field && oc.size() > 3 && (oc[3] == ZAM_OC_INT);
	auto constant_op = (oc[1] == ZAM_OC_CONSTANT);

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
		Emit("auto v = z.c.ToVal(Z_TYPE);");

		if ( lhs_field )
			{
			Emit("auto r = frame[z.v1].AsRecord();");
			Emit("auto& f = DirectField(r, z.v2);");
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

		Emit("auto v = DirectOptField(" + rhs + ".AsRecord(), z.v" + to_string(rhs_offset) +
		     "); // note, RHS field before LHS field\n");

		Emit("if ( ! v )");
		BeginBlock();
		Emit("ZAM_run_time_error(Z_LOC, \"field value missing\");");
		EndBlock();

		Emit("else");
		BeginBlock();
		auto slot = "z.v" + to_string(lhs_offset);
		Emit("auto r = frame[z.v1].AsRecord();");
		Emit("auto& f = DirectField(r, " + slot + "); // note, LHS field after RHS field\n");

		if ( is_managed )
			{
			Emit("zeek::Ref((*v)" + acc + ");");
			Emit("zeek::Unref(f.ManagedVal());");
			}

		Emit("f = *v;");

		if ( lhs_field )
			Emit("r->Modified();");

		EndBlock();
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
			Emit("auto& f = DirectField(r, " + slot + ");");

			if ( is_managed )
				Emit("zeek::Unref(f.ManagedVal());");

			Emit("f = " + rhs + ";");
			Emit("r->Modified();");
			}

		else
			{
			if ( is_managed )
				Emit("zeek::Unref(frame[z.v1].ManagedVal());");

			Emit("frame[z.v1] = ZVal(" + rhs + acc + ");");
			}
		}
	}

void ZAM_OpTemplate::GenAssignOpValCore(const OCVec& oc, const string& orig_eval, const string& accessor, bool is_managed)
	{
	auto v = GetAssignVal();

	// Maps Zeek types to how to get the underlying value from a ValPtr.
	static unordered_map<string, string> val_accessors = {
		{"Addr", "->AsAddrVal()"},     {"Any", ".get()"},
		{"Count", "->AsCount()"},      {"Double", "->AsDouble()"},
		{"Int", "->AsInt()"},          {"Pattern", "->AsPatternVal()"},
		{"String", "->AsStringVal()"}, {"SubNet", "->AsSubNetVal()"},
		{"Table", "->AsTableVal()"},   {"Vector", "->AsVectorVal()"},
		{"File", "->AsFile()"},        {"Func", "->AsFunc()"},
		{"List", "->AsListVal()"},     {"Opaque", "->AsOpaqueVal()"},
		{"Record", "->AsRecordVal()"}, {"Type", "->AsTypeVal()"},
	};

	auto val_accessor = val_accessors[accessor];

	string rhs;
	if ( IsInternalOp() )
		rhs = v + val_accessor;
	else
		rhs = v + ".As" + accessor + "()";

	auto eval = orig_eval;

	if ( is_managed )
		{
		eval += string("auto rhs = ") + rhs + ";\n";
		eval += "zeek::Ref(rhs);\n";
		eval += "Unref($$.ManagedVal());\n";
		eval += "$$ = ZVal(rhs);\n";
		}
	else
		eval += "$$ = ZVal(" + rhs + ");\n";

	Emit(ExpandParams(oc, eval));
	}

string ZAM_OpTemplate::MethodName(const OCVec& oc) const
	{
	return base_name + OpSuffix(oc);
	}

string ZAM_OpTemplate::MethodDeclare(const OCVec& oc, ZAM_InstClass zc)
	{
	ArgsManager args(oc, zc);
	return args.Decls();
	}

string ZAM_OpTemplate::OpSuffix(const OCVec& oc) const
	{
	string os;
	for ( auto& o : oc )
		os += oc_to_char[o];
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

void ZAM_OpTemplate::StartString()
	{
	g->StartString();
	}

void ZAM_OpTemplate::EndString()
	{
	g->EndString();
	}

void ZAM_OpTemplate::Gripe(const char* msg) const
	{
	g->Gripe(msg, op_loc);
	}

void ZAM_OpTemplate::Gripe(string msg, string addl) const
	{
	auto full_msg = msg + ": " + addl;
	Gripe(full_msg.c_str());
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

ZAM_ExprOpTemplate::ZAM_ExprOpTemplate(ZAMGen* _g, string _base_name)
	: ZAM_OpTemplate(_g, std::move(_base_name))
	{
	static bool did_map_init = false;

	if ( ! did_map_init )
		{ // Create the inverse mapping.
		for ( auto& tn : type_names )
			expr_name_types[tn.second] = tn.first;

		did_map_init = true;
		}
	}

void ZAM_ExprOpTemplate::Parse(const string& attr, const string& line, const Words& words)
	{
	if ( attr == "op-type" )
		{
		if ( words.size() == 1 )
			g->Gripe("op-type needs arguments", line);

		for ( auto i = 1U; i < words.size(); ++i )
			{
			auto& w_i = words[i];
			if ( w_i.size() != 1 )
				g->Gripe("bad op-type argument", w_i);

			auto et_c = w_i.c_str()[0];
			if ( type_names.count(et_c) == 0 )
				g->Gripe("bad op-type argument", w_i);

			AddExprType(type_names[et_c]);
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
		if ( type_names.count(type_c) == 0 )
			g->Gripe("bad eval-type type", type);

		auto zt = type_names[type_c];

		if ( expr_types.count(zt) == 0 )
			g->Gripe("eval-type type not present in eval-type", type);

		auto eval = g->SkipWords(line, 2);
		eval += GatherEval();
		AddEvalSet(zt, eval);
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
		if ( type_names.count(type_c1) == 0 || type_names.count(type_c2) == 0 )
			g->Gripe("bad eval-mixed types", line);

		auto et1 = type_names[type_c1];
		auto et2 = type_names[type_c2];

		auto eval = g->SkipWords(line, 3);
		eval += GatherEval();
		AddEvalSet(et1, et2, eval);
		}

	else if ( attr == "precheck" )
		{
		if ( words.size() < 2 )
			g->Gripe("precheck needs evaluation", line);

		auto eval = g->SkipWords(line, 1);
		eval += GatherEval();
		eval.pop_back();

		SetPreCheck(eval);
		}

	else if ( attr == "precheck-action" )
		{
		if ( words.size() < 2 )
			g->Gripe("precheck-action needs evaluation", line);

		auto eval = g->SkipWords(line, 1);
		eval += GatherEval();
		eval.pop_back();

		SetPreCheckAction(eval);
		}

	else if ( attr == "explicit-result-type" )
		{
		if ( words.size() != 1 )
			g->Gripe("extraneous argument to explicit-result-type", line);
		SetHasExplicitResultType();
		}

	else
		// Not an attribute specific to expr-op's.
		ZAM_OpTemplate::Parse(attr, line, words);
	}

void ZAM_ExprOpTemplate::Instantiate()
	{
	if ( ! op_classes_vec.empty() )
		Gripe("expressions cannot use \"classes\"");

	InstantiateOp(OperandClasses(), IncludesVectorOp());

	if ( op_classes.size() > 1 && op_classes[1] == ZAM_OC_CONSTANT )
		InstantiateC1(op_classes, op_classes.size() - 1);
	if ( op_classes.size() > 2 && op_classes[2] == ZAM_OC_CONSTANT )
		InstantiateC2(op_classes, op_classes.size() - 1);
	if ( op_classes.size() > 3 && op_classes[3] == ZAM_OC_CONSTANT )
		InstantiateC3(op_classes);

	bool all_var = true;
	for ( auto i = 1U; i < op_classes.size(); ++i )
		if ( op_classes[i] != ZAM_OC_VAR )
			all_var = false;

	if ( all_var )
		InstantiateV(op_classes);

	if ( op_classes.size() == 3 && op_classes[1] == ZAM_OC_RECORD_FIELD && op_classes[2] == ZAM_OC_INT )
		InstantiateV(op_classes);
	}

void ZAM_ExprOpTemplate::InstantiateC1(const OCVec& ocs, size_t arity)
	{
	string args = "lhs, r1->AsConstExpr()";

	if ( arity == 1 && ocs[0] == ZAM_OC_RECORD_FIELD )
		args += ", rhs->AsFieldExpr()->Field()";

	else if ( arity > 1 )
		{
		args += ", ";

		if ( ocs[2] == ZAM_OC_RECORD_FIELD )
			args += "rhs->AsFieldExpr()->Field()";
		else
			args += "r2->AsNameExpr()";
		}

	auto m = MethodName(ocs);

	EmitTo(C1Def);

	EmitNoNL("case EXPR_" + cname + ":");

	EmitUp("return " + m + "(" + args + ");");

	if ( IncludesFieldOp() )
		{
		EmitTo(C1FieldDef);
		Emit("case EXPR_" + cname + ":\treturn " + m + "i_field(" + args + ", field);");
		}
	}

void ZAM_ExprOpTemplate::InstantiateC2(const OCVec& ocs, size_t arity)
	{
	string args = "lhs, r1->AsNameExpr(), r2->AsConstExpr()";

	if ( arity == 3 )
		args += ", r3->AsNameExpr()";

	auto method = MethodName(ocs);
	auto m = method.c_str();

	EmitTo(C2Def);
	Emit("case EXPR_" + cname + ":\treturn " + m + "(" + args + ");");

	if ( IncludesFieldOp() )
		{
		EmitTo(C2FieldDef);
		Emit("case EXPR_" + cname + ":\treturn " + m + "i_field(" + args + ", field);");
		}
	}

void ZAM_ExprOpTemplate::InstantiateC3(const OCVec& ocs)
	{
	EmitTo(C3Def);
	Emit("case EXPR_" + cname + ":\treturn " + MethodName(ocs) +
	     "(lhs, r1->AsNameExpr(), r2->AsNameExpr(), r3->AsConstExpr());");
	}

void ZAM_ExprOpTemplate::InstantiateV(const OCVec& ocs)
	{
	auto m = MethodName(ocs);

	string args = "lhs, r1->AsNameExpr()";

	if ( ocs.size() >= 3 )
		{
		if ( ocs[2] == ZAM_OC_INT )
			{
			string acc_flav = IncludesFieldOp() ? "Has" : "";
			args += ", rhs->As" + acc_flav + "FieldExpr()->Field()";
			}
		else
			args += ", r2->AsNameExpr()";

		if ( ocs.size() == 4 )
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
		string suffix = NoEval() ? "" : "_field";
		EmitTo(VFieldDef);
		Emit("case EXPR_" + cname + ":\treturn " + m + "i" + suffix + "(" + args + ", field);");
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

void ZAM_ExprOpTemplate::BuildInstructionCore(const string& params, const string& suffix,
                                              ZAM_InstClass zc)
	{
	Emit("auto tag1 = t->Tag();");
	Emit("auto i_t1 = t->InternalType();");

	int ncases = 0;

	if ( zc != ZIC_VEC )
		for ( auto& [et1, et2_map] : eval_mixed_set )
			for ( auto& [et2, eval] : et2_map )
				GenMethodTest(et1, et2, params, suffix, ++ncases > 1, zc);

	bool do_default = false;

	for ( auto zt : ExprTypes() )
		{
		if ( zt == ZAM_TYPE_DEFAULT )
			do_default = true;
		else if ( zt == ZAM_TYPE_NONE )
			continue;
		else
			GenMethodTest(zt, zt, params, suffix, ++ncases > 1, zc);
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

void ZAM_ExprOpTemplate::GenMethodTest(ZAM_Type et1, ZAM_Type et2, const string& params,
                                       const string& suffix, bool do_else, ZAM_InstClass zc)
	{
	// Maps ZAM_Type's to the information needed (variable name,
	// constant to compare it against) to identify using an "if" test
	// that a given AST Expr node employs the given type of operand.
	static map<ZAM_Type, pair<string, string>> if_tests = {
		{ZAM_TYPE_ADDR, {"i_t", "TYPE_INTERNAL_ADDR"}},
		{ZAM_TYPE_ANY, {"tag", "TYPE_ANY"}},
		{ZAM_TYPE_DOUBLE, {"i_t", "TYPE_INTERNAL_DOUBLE"}},
		{ZAM_TYPE_FILE, {"tag", "TYPE_FILE"}},
		{ZAM_TYPE_FUNC, {"tag", "TYPE_FUNC"}},
		{ZAM_TYPE_INT, {"i_t", "TYPE_INTERNAL_INT"}},
		{ZAM_TYPE_LIST, {"tag", "TYPE_LIST"}},
		{ZAM_TYPE_OPAQUE, {"tag", "TYPE_OPAQUE"}},
		{ZAM_TYPE_PATTERN, {"tag", "TYPE_PATTERN"}},
		{ZAM_TYPE_RECORD, {"tag", "TYPE_RECORD"}},
		{ZAM_TYPE_STRING, {"i_t", "TYPE_INTERNAL_STRING"}},
		{ZAM_TYPE_SUBNET, {"i_t", "TYPE_INTERNAL_SUBNET"}},
		{ZAM_TYPE_TABLE, {"tag", "TYPE_TABLE"}},
		{ZAM_TYPE_TYPE, {"tag", "TYPE_TYPE"}},
		{ZAM_TYPE_UINT, {"i_t", "TYPE_INTERNAL_UNSIGNED"}},
		{ZAM_TYPE_VECTOR, {"tag", "TYPE_VECTOR"}},
	};

	if ( if_tests.count(et1) == 0 || if_tests.count(et2) == 0 )
		Gripe("bad op-type");

	auto if_test1 = if_tests[et1];
	auto if_var1 = if_test1.first + "1";
	auto if_val1 = if_test1.second;

	string test = if_var1 + " == " + if_val1;

	if ( Arity() > 1 )
		{
		auto if_test2 = if_tests[et2];
		auto if_var2 = if_test2.first + "2";
		auto if_val2 = if_test2.second;
		test = test + " && " + if_var2 + " == " + if_val2;
		}

	test = "if ( " + test + " )";
	if ( do_else )
		test = "else " + test;

	Emit(test);

	auto op_suffix = suffix + "_" + expr_name_types[et1];
	if ( et2 != et1 )
		op_suffix += expr_name_types[et2];

	auto op = g->GenOpCode(this, op_suffix, zc);
	EmitUp("z = GenInst(" + op + ", " + params + ");");
	}

EvalInstance::EvalInstance(ZAM_Type _lhs_et, ZAM_Type _op1_et, ZAM_Type _op2_et,
                           string _eval, bool _is_def)
	{
	lhs_et = _lhs_et;
	op1_et = _op1_et;
	op2_et = _op2_et;
	eval = std::move(_eval);
	is_def = _is_def;
	}

string EvalInstance::LHSAccessor(bool is_ptr) const
	{
	if ( lhs_et == ZAM_TYPE_NONE || lhs_et == ZAM_TYPE_DEFAULT )
		return "";

	string deref = is_ptr ? "->" : ".";
	string acc = find_type_accessor(lhs_et, true);

	return deref + acc;
	}

string EvalInstance::Accessor(ZAM_Type zt, bool is_ptr) const
	{
	if ( zt == ZAM_TYPE_NONE || zt == ZAM_TYPE_DEFAULT )
		return "";

	string deref = is_ptr ? "->" : ".";
	return deref + "As" + find_type_info(zt).accessor + "()";
	}

string EvalInstance::OpMarker() const
	{
	if ( op1_et == ZAM_TYPE_DEFAULT || op1_et == ZAM_TYPE_NONE )
		return "";

	if ( op1_et == op2_et )
		return "_" + find_type_info(op1_et).suffix;

	return "_" + find_type_info(op1_et).suffix + find_type_info(op2_et).suffix;
	}

void ZAM_ExprOpTemplate::InstantiateEval(const OCVec& oc_orig,
                                         const string& suffix, ZAM_InstClass zc)
	{
	if ( (HasPreCheck() || HasPreCheckAction()) &&
	     (! HasPreCheck() || ! HasPreCheckAction()) )
		Gripe("precheck and precheck-action must be used together");

	auto oc = oc_orig;

	if ( expr_types.empty() )
		{
		// No operand types to expand over. This happens for
		// some "non-uniform" operations.
		ZAM_OpTemplate::InstantiateEval(oc, suffix, zc);
		return;
		}

	auto oc_str = OpSuffix(oc);

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

		// First compute the offsets into oc for the operands.
		auto op1_offset = zc == ZIC_COND ? 0 : 1;
		bool oc1_const = oc[op1_offset] == ZAM_OC_CONSTANT;
		bool oc2_const =
			Arity() > 1 && oc[op1_offset + 1] == ZAM_OC_CONSTANT;

		// Now the frame slots.
		auto op1_slot = op1_offset + 1;
		auto op2_slot = op1_slot + 1;

		if ( oc1_const )
			{
			op1 = "z.c";
			--op2_slot;
			if ( zc == ZIC_COND )
				branch_target += "2";
			}
		else
			{
			op1 = "frame[z.v" + to_string(op1_slot) + "]";

			if ( zc == ZIC_COND )
				{
				if ( Arity() > 1 && ! oc2_const )
					branch_target += "3";
				else
					branch_target += "2";
				}
			}

		if ( oc2_const )
			op2 = "z.c";
		else
			op2 = "frame[z.v" + to_string(op2_slot) + "]";

		if ( zc == ZIC_FIELD )
			{
			// Compute the slot holding the field offset.

			auto f =
				// The first slots are taken up by the
				// assignment slot and the operands ...
				Arity() + 1 +
				// ... and slots are numbered starting at 1.
				+1;

			if ( oc1_const || oc2_const )
				// One of the operand slots won't be needed
				// due to the presence of a constant.
				// (It's never the case that both operands
				// are constants - those instead get folded.)
				--f;

			lhs = "DirectField(" + lhs + ".AsRecord(), z.v" + to_string(f) + ")";
			}
		}

	vector<EvalInstance> eval_instances;

	for ( auto zt : expr_types )
		{
		// Support for "op-type X" meaning "allow empty evaluation",
		// as well as "evaluation is generic".
		if ( zt == ZAM_TYPE_NONE && GetEval().empty() )
			continue;

		auto is_def = eval_set.count(zt) == 0;
		string eval = is_def ? GetEval() : eval_set[zt];
		auto lhs_et = IsConditionalOp() ? ZAM_TYPE_INT : zt;
		eval_instances.emplace_back(lhs_et, zt, zt, eval, is_def);
		}

	if ( zc != ZIC_VEC )
		for ( const auto& em1 : eval_mixed_set )
			{
			auto et1 = em1.first;
			for ( const auto& em2 : em1.second )
				{
				auto et2 = em2.first;

				// For the LHS, either its expression type is
				// ignored, or if it's a conditional, so just
				// note it for the latter.
				auto lhs_et = ZAM_TYPE_INT;
				eval_instances.emplace_back(lhs_et, et1, et2, em2.second, false);
				}
			}

	for ( auto& ei : eval_instances )
		{
		op_types.clear();

		auto lhs_accessor = ei.LHSAccessor();
		if ( HasExplicitResultType() )
			{
			op_types.push_back(ZAM_TYPE_NONE);
			lhs_accessor = "";
			}
		else if ( zc == ZIC_FIELD )
			op_types.push_back(ZAM_TYPE_RECORD);
		else if ( zc != ZIC_COND )
			op_types.push_back(ei.LHS_ET());

		string lhs_ei = lhs;
		if ( zc != ZIC_VEC )
			lhs_ei += lhs_accessor;

		op_types.push_back(ei.Op1_ET());
		if ( Arity() > 1 )
			op_types.push_back(ei.Op2_ET());

		if ( zc == ZIC_FIELD )
			op_types.push_back(ZAM_TYPE_INT);

		else if ( zc == ZIC_COND )
			op_types.push_back(ZAM_TYPE_INT);

		else if ( zc == ZIC_VEC )
			{
			// Above isn't applicable, since we use helper
			// functions.
			op_types.clear();
			op_types.push_back(ZAM_TYPE_VECTOR);
			op_types.push_back(ZAM_TYPE_VECTOR);

			if ( Arity() > 1 )
				op_types.push_back(ZAM_TYPE_VECTOR);
			}

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

			eval = regex_replace(eval, regex(rhs), replacement, std::regex_constants::match_not_null);
			}

		auto is_none = ei.LHS_ET() == ZAM_TYPE_NONE;
		auto is_default = ei.LHS_ET() == ZAM_TYPE_DEFAULT;

		if ( ! is_none && ! is_default && find_type_info(ei.LHS_ET()).is_managed &&
		     ! HasExplicitResultType() )
			{
			auto pre = "auto hold_lhs = " + lhs;

			if ( zc == ZIC_VEC )
				// For vectors, we have to check for whether
				// the previous value is present, or a hole.
				pre += string(" ? ") + lhs + "->";
			else
				pre += ".";

			pre += "ManagedVal()";

			if ( zc == ZIC_VEC )
				pre += " : nullptr";

			pre += ";\n\t";

			auto post = "\tUnref(hold_lhs);";

			eval = pre + eval + post;
			}

		eval = regex_replace(eval, regex("\\$1"), op1_ei);
		eval = regex_replace(eval, regex("\\$2"), op2_ei);

		string pre, post;

		if ( HasPreCheck() )
			{
			pre = "if ( " + GetPreCheck() + ")\n\t{\n\t" +
				GetPreCheckAction() + "\n\t}\n\telse\n\t{\n\t";
			post = "\n\t}";
			}

		pre = regex_replace(pre, regex("\\$1"), op1_ei);
		pre = regex_replace(pre, regex("\\$2"), op2_ei);

		if ( has_target )
			eval = regex_replace(eval, regex("\\$\\$"), lhs_ei);

		else if ( zc == ZIC_COND )
			{
			// Aesthetics: get rid of trailing newlines.
			eval = regex_replace(eval, regex("\n"), "");

			eval = "if ( ! (" + eval + ") ) " +
			       "Branch(" + branch_target + ")";
			}

		else if ( ! is_none && (ei.IsDefault() || IsConditionalOp()) )
			{
			eval = lhs_ei + " = " + eval;

			// Ensure a single terminating semicolon.
			eval = regex_replace(eval, regex(";*\n"), ";\n");
			}

		eval = pre + eval + post;

		auto full_suffix = suffix + ei.OpMarker();

		GenEval(emit_target, oc_str, full_suffix, eval, zc);

		if ( zc == ZIC_VEC )
			{
			string dispatch_params = "frame[z.v1].AsVectorRef(), frame[z.v2].AsVector()";

			if ( Arity() == 2 )
				dispatch_params += ", frame[z.v3].AsVector()";

			auto op_code = g->GenOpCode(this, "_" + oc_str + full_suffix);
			auto dispatch = "vec_exec(" + op_code + ", Z_TYPE, " + dispatch_params + ", z);";

			GenEval(Eval, oc_str, full_suffix, dispatch, zc);
			}
		}
	}

void ZAM_UnaryExprOpTemplate::Parse(const string& attr, const string& line, const Words& words)
	{
	if ( attr == "no-const" )
		{
		if ( words.size() != 1 )
			g->Gripe("extraneous argument to no-const", line);

		SetNoConst();
		}

	else
		ZAM_ExprOpTemplate::Parse(attr, line, words);
	}

void ZAM_UnaryExprOpTemplate::Instantiate()
	{
	UnaryInstantiate();

	OCVec ocs = {ZAM_OC_VAR, ZAM_OC_CONSTANT};

	if ( ! NoConst() )
		InstantiateC1(ocs, 1);

	ocs[1] = ZAM_OC_VAR;
	InstantiateV(ocs);
	}

void ZAM_UnaryExprOpTemplate::BuildInstruction(const OCVec& oc,
                                               const string& params, const string& suffix,
                                               ZAM_InstClass zc)
	{
	const auto& ets = ExprTypes();

	if ( ets.size() == 1 && ets.count(ZAM_TYPE_NONE) == 1 )
		{
		ZAM_ExprOpTemplate::BuildInstruction(oc, params, suffix, zc);
		return;
		}

	auto constant_op = oc[1] == ZAM_OC_CONSTANT;
	string type_src = constant_op ? "c" : "n2";

	if ( oc[0] == ZAM_OC_ASSIGN_FIELD )
		{
		type_src = constant_op ? "n" : "n1";
		Emit("auto " + type_src + " = flhs->GetOp1()->AsNameExpr();");
		Emit("auto t = flhs->GetType();");
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
		Emit("z.SetType(t);");

	else if ( zc == ZIC_VEC )
		{
		if ( constant_op )
			Emit("z.SetType(n->GetType());");
		else
			Emit("z.SetType(n1->GetType());");
		}
	}

ZAM_AssignOpTemplate::ZAM_AssignOpTemplate(ZAMGen* _g, string _base_name)
	: ZAM_UnaryExprOpTemplate(_g, std::move(_base_name))
	{
	// Assignments apply to every valid form of ExprType.
	for ( auto& etn : type_names )
		{
		auto zt = etn.second;
		if ( zt != ZAM_TYPE_NONE && zt != ZAM_TYPE_DEFAULT )
			AddExprType(zt);
		}
	}

void ZAM_AssignOpTemplate::Parse(const string& attr, const string& line, const Words& words)
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
	if ( op_classes.size() != 1 )
		Gripe("operation needs precisely one \"type\"");
	if ( ! op_classes_vec.empty() )
		Gripe("operation cannot use \"classes\"");

	OCVec ocs;
	ocs.push_back(op_classes[0]);

	// Build constant/variable versions ...
	ocs.push_back(ZAM_OC_CONSTANT);

	if ( ocs[0] == ZAM_OC_RECORD_FIELD || ocs[0] == ZAM_OC_ASSIGN_FIELD )
		ocs.push_back(ZAM_OC_INT);

	InstantiateOp(ocs, false);
	if ( IsFieldOp() )
		InstantiateC1(ocs, 1);

	ocs[1] = ZAM_OC_VAR;
	InstantiateOp(ocs, false);

	// ... and for assignments to fields, additional field versions.
	if ( ocs[0] == ZAM_OC_ASSIGN_FIELD )
		{
		ocs.push_back(ZAM_OC_INT);
		InstantiateOp(ocs, false);

		ocs[1] = ZAM_OC_CONSTANT;
		InstantiateOp(ocs, false);
		}

	else if ( IsFieldOp() )
		InstantiateV(ocs);
	}

void ZAM_BinaryExprOpTemplate::Instantiate()
	{
	// As usual, the first slot receives the operator's result.
	OCVec ocs = {ZAM_OC_VAR};
	ocs.resize(3);

	// Build each combination for constant/variable operand,
	// except skip constant/constant as that is always folded.

	// We only include vector operations when both operands
	// are non-constants.

	ocs[1] = ZAM_OC_CONSTANT;
	ocs[2] = ZAM_OC_VAR;
	InstantiateOp(ocs, false);

	if ( ! IsInternalOp() )
		InstantiateC1(ocs, 2);

	ocs[1] = ZAM_OC_VAR;
	ocs[2] = ZAM_OC_CONSTANT;
	InstantiateOp(ocs, false);

	if ( ! IsInternalOp() )
		InstantiateC2(ocs, 2);

	ocs[2] = ZAM_OC_VAR;
	InstantiateOp(ocs, IncludesVectorOp());

	if ( ! IsInternalOp() )
		InstantiateV(ocs);
	}

void ZAM_BinaryExprOpTemplate::BuildInstruction(const OCVec& oc,
                                                const string& params, const string& suffix,
                                                ZAM_InstClass zc)
	{
	auto constant_op = oc[1] == ZAM_OC_CONSTANT;
	string type_src = constant_op ? "c" : "n2";
	auto type_suffix = zc == ZIC_VEC ? "->Yield();" : ";";
	Emit("auto t = " + type_src + "->GetType()" + type_suffix);

	GenerateSecondTypeVars(oc, zc);
	BuildInstructionCore(params, suffix, zc);

	if ( zc == ZIC_VEC )
		Emit("z.SetType(n1->GetType());");
	}

void ZAM_BinaryExprOpTemplate::GenerateSecondTypeVars(const OCVec& oc,
							ZAM_InstClass zc)
	{
	auto constant_op = oc[1] == ZAM_OC_CONSTANT;
	auto type_suffix = zc == ZIC_VEC ? "->Yield();" : ";";

	string type_src2;

	if ( zc == ZIC_COND )
		{
		if ( oc[0] == ZAM_OC_CONSTANT )
			type_src2 = "n";
		else if ( oc[1] == ZAM_OC_CONSTANT )
			type_src2 = "c";
		else
			type_src2 = "n2";
		}
	else
		{
		if ( oc[1] == ZAM_OC_CONSTANT )
			type_src2 = "n2";
		else if ( oc[2] == ZAM_OC_CONSTANT )
			type_src2 = "c";
		else
			type_src2 = "n3";
		}

	Emit("auto t2 = " + type_src2 + "->GetType()" + type_suffix);
	Emit("auto tag2 = t2->Tag();");
	Emit("auto i_t2 = t2->InternalType();");
	}

void ZAM_RelationalExprOpTemplate::Instantiate()
	{
	ZAM_BinaryExprOpTemplate::Instantiate();

	EmitTo(Cond);

	Emit("case EXPR_" + cname + ":");
	IndentUp();
	Emit("if ( n1 && n2 )");
	EmitUp("return " + cname + "VVb_cond(n1, n2);");
	Emit("else if ( n1 )");
	EmitUp("return " + cname + "VCb_cond(n1, c);");
	Emit("else");
	EmitUp("return " + cname + "CVb_cond(c, n2);");
	IndentDown();
	NL();
	}

void ZAM_RelationalExprOpTemplate::BuildInstruction(const OCVec& oc,
                                                    const string& params, const string& suffix,
                                                    ZAM_InstClass zc)
	{
	string op1;

	if ( zc == ZIC_COND )
		{
		if ( oc[0] == ZAM_OC_CONSTANT )
			op1 = "c";
		else if ( oc[1] == ZAM_OC_CONSTANT )
			op1 = "n";
		else
			op1 = "n1";
		}
	else
		{
		if ( oc[1] == ZAM_OC_CONSTANT )
			op1 = "c";
		else
			op1 = "n2";
		}

	auto type_suffix = zc == ZIC_VEC ? "->Yield();" : ";";
	Emit("auto t = " + op1 + "->GetType()" + type_suffix);
	GenerateSecondTypeVars(oc, zc);
	BuildInstructionCore(params, suffix, zc);

	if ( zc == ZIC_VEC )
		Emit("z.SetType(n1->GetType());");
	}

void ZAM_InternalOpTemplate::Parse(const string& attr, const string& line, const Words& words)
	{
	if ( attr == "num-call-args" )
		ParseCall(line, words);

	else if ( attr == "indirect-call" || attr == "indirect-local-call" )
		{
		if ( words.size() != 1 )
			g->Gripe("indirect-call takes one argument", line);

		// Note, currently only works with a *subsequent* num-call-args,
		// whose setting needs to be 'n'.
		is_indirect_call = true;

		if ( attr == "indirect-local-call" )
			is_local_indirect_call = true;
		}

	else
		ZAM_OpTemplate::Parse(attr, line, words);
	}

void ZAM_InternalOpTemplate::ParseCall(const string& line, const Words& words)
	{
	if ( words.size() != 2 )
		g->Gripe("num-call-args takes one argument", line);

	eval = "std::vector<ValPtr> args;\n";

	auto& arg = words[1];
	int n = arg == "n" ? -1 : stoi(arg);

	auto arg_offset = HasAssignVal() ? 1 : 0;
	auto arg_slot = arg_offset + 1;

	string func = "Z_AUX->func";

	if ( n == 1 )
		eval += "args.push_back($1.ToVal(Z_TYPE));\n";

	else if ( n != 0 )
		{
		eval += "auto aux = Z_AUX;\n";

		if ( n < 0 )
			{
			if ( is_indirect_call )
				{
				func = "func";

				if ( is_local_indirect_call )
					eval += "auto func = $1.AsFunc();\n";
				else
					{
					eval += "auto func_v = aux->id_val->GetVal();\n";
					eval += "auto func = func_v ? func_v->AsFunc() : nullptr;\n";
					}

				eval += "if ( ! func )\n";
				eval += "\t{\n";
				eval += "\tZAM_run_time_error(Z_LOC, \"value used but not set\");\n";
				eval += "\tbreak;\n";
				eval += "\t}\n";
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

	eval += "f->SetOnlyCall(Z_AUX->call_expr.get());\n";
	eval += "ZAM_PROFILE_PRE_CALL\n";

	if ( HasAssignVal() )
		{
		auto av = GetAssignVal();
		eval += "auto " + av + " = " + func + "->Invoke(&args, f);\n";
		eval += "if ( ! " + av + " ) { ZAM_error = true; break; }\n";

		// Postpone the profiling follow-up until after we process
		// the assignment.
		post_eval = "ZAM_PROFILE_POST_CALL\n";
		}
	else
		{
		eval += "(void) " + func + "->Invoke(&args, f);\n";
		eval += "ZAM_PROFILE_POST_CALL\n";
		}
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
	do
		{
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
	size_t n = strlen(input_s);

	fprintf(stderr, "%s, line %d: %s - %s", loc.file_name, loc.line_num, msg, input_s);
	if ( n == 0 || input_s[n - 1] != '\n' )
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
	auto prog_name = (argv++)[0];

	if ( --argc < 1 )
		{
		fprintf(stderr, "usage: %s <ZAM-templates-file>\n", prog_name);
		exit(1);
		}

	while ( argc-- > 0 )
		{
		auto file_name = (argv++)[0];
		bool is_stdin = file_name == std::string("-");
		auto f = is_stdin ? stdin : fopen(file_name, "r");

		if ( ! f )
			{
			fprintf(stderr, "%s: cannot open \"%s\"\n", prog_name, file_name);
			exit(1);
			}

		ti = make_unique<TemplateInput>(f, prog_name, file_name);

		while ( ParseTemplate() )
			;

		if ( ! is_stdin )
			fclose(f);
		}

	InitEmitTargets();

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

		if ( regex_search(s, regex("\\$[$123]")) )
			Gripe("macro has $-param", s);

		mac.push_back(s);
		}

	macros.emplace_back(std::move(mac));
	}

void ZAMGen::GenMacros()
	{
	for ( auto& m : macros )
		{
		for ( auto i = 0U; i < m.size(); ++i )
			{
			auto ms = m[i];
			if ( i == 0 )
				{
				auto name = regex_replace(ms, regex("[( ].*\n"), "");
				Emit(MacroDesc, "{ \"" + name + "\",");

				ms = "#define " + ms;
				}

			auto desc = ms;
			desc.erase(desc.find('\n'));
			desc = regex_replace(desc, regex("\\\\"), "\\\\");
			desc = regex_replace(desc, regex("\""), "\\\"");

			if ( i < m.size() - 1 )
				{
				ms = regex_replace(ms, regex("\n"), " \\\n");
				desc.append(" \\\\\\n");
				}

			Emit(MacroDesc, "  \"" + desc + "\"");
			if ( i == m.size() - 1 )
				Emit(MacroDesc, "},");

			Emit(EvalMacros, ms);
			}

		Emit(EvalMacros, "\n");
		}
	}

string ZAMGen::GenOpCode(const ZAM_OpTemplate* ot, const string& suffix, ZAM_InstClass zc)
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
		fputc('\t', f);

	if ( string_lit )
		{
		fputc('"', f);
		for ( auto sp = s.c_str(); *sp; ++sp )
			{
			if ( *sp == '\\' )
				fputs("\\\\", f);
			else if ( *sp == '"' )
				fputs("\\\"", f);
			else if ( *sp == '\n' )
				fputs("\\n", f);
			else
				fputc(*sp, f);
			}
		fputc('"', f);
		}

	else
		fputs(s.c_str(), f);

	if ( ! no_NL && (s.empty() || s.back() != '\n') )
		fputc('\n', f);
	}

void ZAMGen::InitEmitTargets()
	{
	// Maps an EmitTarget enum to its corresponding filename.
	static const unordered_map<EmitTarget, const char*> gen_file_names = {
		{None, nullptr},
		{AssignFlavor, "ZAM-AssignFlavorsDefs.h"},
		{C1Def, "ZAM-GenExprsDefsC1.h"},
		{C1FieldDef, "ZAM-GenFieldsDefsC1.h"},
		{C2Def, "ZAM-GenExprsDefsC2.h"},
		{C2FieldDef, "ZAM-GenFieldsDefsC2.h"},
		{C3Def, "ZAM-GenExprsDefsC3.h"},
		{Cond, "ZAM-Conds.h"},
		{DirectDef, "ZAM-DirectDefs.h"},
		{Eval, "ZAM-EvalDefs.h"},
		{EvalMacros, "ZAM-EvalMacros.h"},
		{MacroDesc, "ZAM-MacroDesc.h"},
		{MethodDecl, "ZAM-MethodDecls.h"},
		{MethodDef, "ZAM-MethodDefs.h"},
		{Op1Flavor, "ZAM-Op1FlavorsDefs.h"},
		{OpDef, "ZAM-OpsDefs.h"},
		{OpDesc, "ZAM-OpDesc.h"},
		{OpName, "ZAM-OpsNamesDefs.h"},
		{OpSideEffects, "ZAM-OpSideEffects.h"},
		{VDef, "ZAM-GenExprsDefsV.h"},
		{VFieldDef, "ZAM-GenFieldsDefsV.h"},
		{Vec1Eval, "ZAM-Vec1EvalDefs.h"},
		{Vec2Eval, "ZAM-Vec2EvalDefs.h"},
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

	// Avoid bugprone-branch-clone warnings from clang-tidy in generated code.
	Emit(OpName, "// NOLINTBEGIN(bugprone-branch-clone)");
	Emit(Eval, "// NOLINTBEGIN(bugprone-branch-clone)");
	Emit(EvalMacros, "// NOLINTBEGIN(bugprone-macro-parentheses)");
	Emit(EvalMacros, "// NOLINTBEGIN(cppcoreguidelines-macro-usage)");

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

	switch_targets[et] = std::move(desc);
	}

void ZAMGen::CloseEmitTargets()
	{
	FinishSwitches();

	Emit(OpName, "// NOLINTEND(bugprone-branch-clone)");
	Emit(Eval, "// NOLINTEND(bugprone-branch-clone)");
	Emit(EvalMacros, "// NOLINTEND(cppcoreguidelines-macro-usage)");
	Emit(EvalMacros, "// NOLINTEND(bugprone-macro-parentheses)");

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
	else if ( op == "internal-op" )
		t = make_unique<ZAM_InternalOpTemplate>(this, op_name);
	else if ( op == "predicate-op" )
		{
		t = make_unique<ZAM_InternalOpTemplate>(this, op_name);
		t->SetIsPredicate();
		}
	else if ( op == "internal-assignment-op" )
		t = make_unique<ZAM_InternalAssignOpTemplate>(this, op_name);

	else
		Gripe("bad template name", op);

	if ( args_mismatch )
		Gripe(args_mismatch, line);

	t->Build();
	templates.emplace_back(std::move(t));

	return true;
	}

int main(int argc, char** argv)
	{
	try
		{
		ZAMGen zg(argc, argv);
		exit(0);
		}
	catch ( const std::regex_error& e )
		{
		fprintf(stderr, "%s: regular expression error - %s\n", argv[0], e.what());
		exit(1);
		}
	}
