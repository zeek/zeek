// See the file "COPYING" in the main distribution directory for copyright.

#include <ctype.h>

#include "ZAM-Gen.h"

using namespace std;

ZAM_OpTemplate::ZAM_OpTemplate(TemplateInput* _ti, string _base_name)
: ti(_ti), base_name(std::move(_base_name))
	{
	}

void ZAM_OpTemplate::Build()
	{
	string line;
	while ( ti->ScanLine(line) )
		{
		if ( line.size() <= 1 )
			break;

		auto words = ti->SplitIntoWords(line);
		if ( words.size() == 0 )
			break;

		Parse(words[0], line, words);
		}
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
					ti->Gripe("bad operand type", words[1]);
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
		SetOp1Flavor(OP1_READ);
		}

	else if ( attr == "op1-read-write" )
		{
		num_args = 0;
		SetOp1Flavor(OP1_READ_WRITE);
		}

	else if ( attr == "op1-internal" )
		{
		num_args = 0;
		SetOp1Flavor(OP1_INTERNAL);
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
		SetCustomMethod(ti->AllButFirstWord(line));

	else if ( attr == "method-post" )
		SetPostMethod(ti->AllButFirstWord(line));

	else if ( attr == "side-effects" )
		{
		if ( nwords == 3 )
			SetSpecificSideEffects(words[1], words[2]);
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

	else if ( attr == "eval" )
		{
		AddEval(ti->AllButFirstWord(line));

		auto addl = GatherEvals();
		if ( addl.size() > 0 )
			AddEval(addl);
		}

	else
		ti->Gripe("unknown template attribute", attr);

	if ( num_args >= 0 && num_args != nwords - 1 )
		ti->Gripe("extraneous arguments", line);
	}

string ZAM_OpTemplate::GatherEvals()
	{
	string res;
	string l;
	while ( ti->ScanLine(l) )
		{
		if ( l.size() <= 1 || ! isspace(l.c_str()[0]) )
			{
			ti->PutBack(l);
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
		ti->Gripe("bad set-type parameter, should be $n", arg);

	int param = atoi(&param_str[1]);

	if ( param <= 0 || param > 3 )
		ti->Gripe("bad set-type parameter, should be $1/$2/$3", arg);

	return param;
	}

void ZAM_AssignOpTemplate::Parse(const string& attr, const string& line,
                                 const Words& words)
	{
	if ( attr == "field-op" )
		{
		if ( words.size() != 1 )
			ti->Gripe("field-op does not take any arguments", line);

		SetIncludesFieldOp();
		}

	else
		ZAM_OpTemplate::Parse(attr, line, words);
	}

std::unordered_map<char, ZAM_ExprType> ZAM_ExprOpTemplate::expr_type_names = {
	{ '*', ZAM_EXPR_TYPE_ANY },
	{ 'A', ZAM_EXPR_TYPE_ADDR },
	{ 'D', ZAM_EXPR_TYPE_DOUBLE },
	{ 'I', ZAM_EXPR_TYPE_INT },
	{ 'N', ZAM_EXPR_TYPE_SUBNET },
	{ 'P', ZAM_EXPR_TYPE_PORT },
	{ 'S', ZAM_EXPR_TYPE_STRING },
	{ 'T', ZAM_EXPR_TYPE_TABLE },
	{ 'U', ZAM_EXPR_TYPE_UINT },
	{ 'V', ZAM_EXPR_TYPE_VECTOR },
	{ 'X', ZAM_EXPR_TYPE_NONE },
	{ 'd', ZAM_EXPR_TYPE_DOUBLE_CUSTOM },
	{ 'i', ZAM_EXPR_TYPE_INT_CUSTOM },
	{ 'u', ZAM_EXPR_TYPE_UINT_CUSTOM },
};

void ZAM_ExprOpTemplate::Parse(const string& attr, const string& line,
                               const Words& words)
	{
	if ( attr == "op-type" )
		{
		if ( words.size() == 1 )
			ti->Gripe("op-type needs arguments", line);

		for ( auto i = 1; i < words.size(); ++i )
			{
			auto& w_i = words[i];
			if ( w_i.size() != 1 )
				ti->Gripe("bad op-type argument", w_i);

			auto et_c = w_i.c_str()[0];
			if ( expr_type_names.count(et_c) == 0 )
				ti->Gripe("bad op-type argument", w_i);

			AddExprType(expr_type_names[et_c]);
			}
		}

	else if ( attr == "eval-flavor" )
		{
		if ( words.size() < 3 )
			ti->Gripe("eval-flavor needs type and evaluation", line);

		auto& flavor = words[1];
		if ( flavor.size() != 1 )
			ti->Gripe("bad eval-flavor flavor", flavor);

		auto flavor_c = flavor.c_str()[0];
		if ( expr_type_names.count(flavor_c) == 0 )
			ti->Gripe("bad eval-flavor flavor", flavor);

		auto et = expr_type_names[flavor_c];

		if ( expr_types.count(et) == 0 )
			ti->Gripe("eval-flavor flavor not present in op-type", flavor);

		// Skip the first two words.
		auto eval = ti->AllButFirstWord(ti->AllButFirstWord(line));
		eval += GatherEvals();
		AddEvalSet(et, eval);
		}

	else if ( attr == "eval-mixed" )
		{
		if ( words.size() < 4 )
			ti->Gripe("eval-mixed needs types and evaluation", line);

		auto& flavor1 = words[1];
		auto& flavor2 = words[2];
		if ( flavor1.size() != 1 || flavor2.size() != 1 )
			ti->Gripe("bad eval-mixed flavors", line);

		auto flavor_c1 = flavor1.c_str()[0];
		auto flavor_c2 = flavor2.c_str()[0];
		if ( expr_type_names.count(flavor_c1) == 0 ||
		     expr_type_names.count(flavor_c2) == 0 )
			ti->Gripe("bad eval-mixed flavors", line);

		auto et1 = expr_type_names[flavor_c1];
		auto et2 = expr_type_names[flavor_c2];

		// Skip the first three words.
		auto eval = ti->AllButFirstWord(ti->AllButFirstWord(line));
		eval = ti->AllButFirstWord(eval);
		eval += GatherEvals();
		AddEvalSet(et1, et2, eval);
		}

	else if ( attr == "eval-pre" )
		{
		if ( words.size() < 2 )
			ti->Gripe("eval-pre needs evaluation", line);

		auto eval = ti->AllButFirstWord(line);
		eval += GatherEvals();

		SetPreEval(eval);
		}

	else
		ZAM_OpTemplate::Parse(attr, line, words);
	}

void ZAM_UnaryExprOpTemplate::Parse(const string& attr, const string& line,
                                    const Words& words)
	{
	if ( attr == "no-const" )
		{
		if ( words.size() != 1 )
			ti->Gripe("extraneous argument to no-const", line);

		SetNoConst();
		}

	else if ( attr == "type-selector" )
		{
		if ( words.size() != 2 )
			ti->Gripe("type-selector takes one numeric argument", line);
		SetTypeSelector(stoi(words[1]));
		}

	else
		ZAM_ExprOpTemplate::Parse(attr, line, words);
	}

void ZAM_InternalBinaryOpTemplate::Parse(const string& attr, const string& line,
                                         const Words& words)
	{
	if ( attr == "op-accessor" )
		{
		if ( words.size() != 2 )
			ti->Gripe("op-accessor takes one argument", line);

		SetOpAccessor(words[1]);
		}

	else if ( attr == "op1-accessor" )
		{
		if ( words.size() != 2 )
			ti->Gripe("op-accessor1 takes one argument", line);

		SetOp1Accessor(words[1]);
		}

	else if ( attr == "op2-accessor" )
		{
		if ( words.size() != 2 )
			ti->Gripe("op-accessor2 takes one argument", line);

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
	}

bool ZAMGen::ParseTemplate()
	{
	string line;

	if ( ! ti->ScanLine(line) )
		return false;

	if ( line.size() <= 1 )
		// A blank line - no template to parse.
		return true;

	auto words = ti->SplitIntoWords(line);

	if ( words.size() < 2 )
		ti->Gripe("too few words at start of template", line);

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
		t = make_unique<ZAM_OpTemplate>(ti.get(), op_name);
	else if ( op == "unary-op" )
		t = make_unique<ZAM_UnaryOpTemplate>(ti.get(), op_name);
	else if ( op == "direct-unary-op" )
		t = make_unique<ZAM_DirectUnaryOpTemplate>(ti.get(), op_name, words[2]);
	else if ( op == "assign-op" )
		t = make_unique<ZAM_AssignOpTemplate>(ti.get(), op_name);
	else if ( op == "expr-op" )
		t = make_unique<ZAM_ExprOpTemplate>(ti.get(), op_name);
	else if ( op == "unary-expr-op" )
		t = make_unique<ZAM_UnaryExprOpTemplate>(ti.get(), op_name);
	else if ( op == "binary-expr-op" )
		t = make_unique<ZAM_BinaryExprOpTemplate>(ti.get(), op_name);
	else if ( op == "rel-expr-op" )
		t = make_unique<ZAM_RelationalExprOpTemplate>(ti.get(), op_name);
	else if ( op == "internal-binary-op" )
		t = make_unique<ZAM_InternalBinaryOpTemplate>(ti.get(), op_name);
	else if ( op == "internal-op" )
		t = make_unique<ZAM_InternalOpTemplate>(ti.get(), op_name);
	else if ( op == "internal-assignment-op" )
		t = make_unique<ZAM_InternalAssignOpTemplate>(ti.get(), op_name);

	else
		ti->Gripe("bad template name", op);

	if ( args_mismatch )
		ti->Gripe(args_mismatch, line);

	t->Build();
	templates.emplace_back(std::move(t));

	return true;
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
		++line_num;
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

string TemplateInput::AllButFirstWord(const string& line) const
	{
	for ( auto s = line.c_str(); *s && *s != '\n'; ++s )
		if ( isspace(*s) )
			return std::string(s);

	return "";
	}

void TemplateInput::Gripe(const char* msg, const string& input)
	{
	auto input_s = input.c_str();
	int n = strlen(input_s);

	fprintf(stderr, "%s, line %d: %s - %s", file_name, line_num, msg, input_s);
	if ( n == 0 || input_s[n-1] != '\n' )
		fprintf(stderr, "\n");

	exit(1);
	}


int main(int argc, char** argv)
	{
	ZAMGen(argc, argv);
	exit(0);
	}
