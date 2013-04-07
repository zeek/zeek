
#include <memory>

#include <glob.h>

extern "C" {
#include <libbinpac++.h>
}

#undef DBG_LOG

#include "config.h"

#include "../Scope.h"
#include "../ID.h"
#include "../Desc.h"
#include "../Func.h"
#include "../Analyzer.h"
#undef List

// #include "../NetVar.h"
//
// FIXME: Can't include NetVar.h as our build doesn't trigger bifcl before
// cmake descends into the hilti subdirectory.
extern RecordType* connection_type;
namespace BifConst { namespace Pac2 {  extern int dump_debug;  }  }
namespace BifConst { namespace Pac2 {  extern int dump_code;  }  }
namespace BifConst { namespace Pac2 {  extern int dump_code_all;  }  }
namespace BifConst { namespace Pac2 {  extern int dump_code_pre_finalize;  }  }
namespace BifConst { namespace Pac2 {  extern int dump_debug;  }  }
namespace BifConst { namespace Pac2 {  extern int no_verify;  }  }
namespace BifConst { namespace Pac2 {  extern int compile_all;  }  }
namespace BifConst { namespace Pac2 {  extern StringVal* cg_debug;  }  }
namespace BifConst { namespace Pac2 {  extern int save_pac2;  }  }
namespace BifConst { namespace Pac2 {  extern int save_hilti;  }  }
namespace BifConst { namespace Pac2 {  extern int save_llvm;  }  }
namespace BifConst { namespace Pac2 {  extern int debug;  }  }
namespace BifConst { namespace Pac2 {  extern int optimize;  }  }
namespace BifConst { namespace Pac2 {  extern int use_cache;  }  }
/// End of NetVar.h declarations.

#include <ast/declaration.h>
#include <hilti/hilti.h>
#include <hilti/jit/libhilti-jit.h>
#include <binpac/binpac++.h>
#include <binpac/type.h>
#include <binpac/declaration.h>
#include <binpac/expression.h>
#include <binpac/statement.h>
#include <binpac/function.h>

#include <llvm/ExecutionEngine/ExecutionEngine.h>

#include "Loader.h"
#include "Pac2AST.h"
#include "Pac2Analyzer.h"
#include "Converter.h"
#include "DPM.h"
#include "LocalReporter.h"
#include "Runtime.h"
#include "net_util.h"

using namespace bro::hilti;
using namespace binpac;

using std::shared_ptr;

static string transportToString(TransportProto p)
	{
	switch ( p ) {
	case TRANSPORT_TCP: return "tcp";
	case TRANSPORT_UDP: return "udp";
	case TRANSPORT_ICMP: return "icmp";
	case TRANSPORT_UNKNOWN: return "<unknown>";
	default:
		return "<not supported>";
	}
	}

struct Port {
	uint32 port;
	TransportProto proto;

	Port(uint32 port = 0, TransportProto proto = TRANSPORT_UNKNOWN) : port(port), proto(proto)	{}
	operator string() const	{ return ::util::fmt("%u/%s", port, transportToString(proto)); }
	};

// Description of a BinPAC++ module.
struct bro::hilti::Pac2ModuleInfo {
	string path; 					// The path the module was read from.
	shared_ptr<::binpac::CompilerContext> context;	// The context used for the module.
	shared_ptr<::binpac::Module> module;		// The module itself.
	};

// Description of a BinPAC++ analyzer.
struct bro::hilti::Pac2AnalyzerInfo {
	string location;				// Location where the analyzer was defined.
	string name;					// Name of the analyzer.
	uint32 subtype;					// AnalyzerTag subtype for this analyzer.
	TransportProto proto;				// The transport layer the analyzer uses.
	std::list<Port> ports;				// The ports associated with the analyzer.
	string unit_name_orig;				// The fully-qualified name of the unit type to parse the originator side.
	string unit_name_resp;				// The fully-qualified name of the unit type to parse the originator side.
	shared_ptr<binpac::type::Unit> unit_orig;	// The type of the unit to parse the originator side.
	shared_ptr<binpac::type::Unit> unit_resp;	// The type of the unit to parse the originator side.
	binpac_parser* parser_orig;                     // The parser for the originator side (coming out of JIT).
	binpac_parser* parser_resp;                     // The parser for the responder side (coming out of JIT).
};

// XXX
struct bro::hilti::Pac2ExpressionAccessor {
	int nr;					// Position of this expression in argument list.
	string expr;				// The string representation of the expression.
	bool dollar_id;				// True if this is a "magic" $-ID.
	shared_ptr<::binpac::Type> btype = nullptr;	// The BinPAC++ type of the expression.
	shared_ptr<::hilti::Type> htype = nullptr;	// The corresponding HILTI type of the expression.
	std::shared_ptr<::binpac::declaration::Function> pac2_func = nullptr;		// Implementation of function that evaluates the expression.
	std::shared_ptr<::hilti::declaration::Function> hlt_func = nullptr;	// Declaration of a function that evaluates the expression.
	};

// Description of an event defined by an *.evt file
struct bro::hilti::Pac2EventInfo
	{
	typedef std::list<shared_ptr<Pac2ExpressionAccessor>> accessor_list;

	// Information parsed directly from the *.evt file.
	string name;		// The name of the event.
	std::list<string> exprs;	// The argument expressions.
	string hook;		// The name of the hook triggering the event.
	string location;	// Location string where event is defined.

	// Computed information.
	string unit;                                    // The fully qualified name of the unit type.
	string hook_local;                              // The local part of the triggering hook (i.e., w/o the unit name).
	shared_ptr<::binpac::type::Unit> unit_type;	// The BinPAC++ type of referenced unit.
	shared_ptr<::binpac::Module> unit_module;       // The module the referenced unit is defined in.
	shared_ptr<::binpac::declaration::Hook> pac2_hook;	// The generated BinPAC hook.
	shared_ptr<::hilti::declaration::Function> hilti_raise;	// The generated HILTI raise() function.
	BroType* bro_event_type;                        // The type of the Bro event.
	EventHandlerPtr bro_event_handler;              // The type of the corresponding Bro event. Set only if we have a handler.
	accessor_list expr_accessors;                   // One HILTI function per expression to access the value.
	};

// Implementation of the Loader class attributes.
struct Loader::PIMPL
	{
	typedef std::list<shared_ptr<Pac2ModuleInfo>>     pac2_module_list;
	typedef std::list<shared_ptr<Pac2EventInfo>>      pac2_event_list;
	typedef std::list<shared_ptr<Pac2AnalyzerInfo>>   pac2_analyzer_list;
	typedef std::vector<shared_ptr<Pac2AnalyzerInfo>> pac2_analyzer_vector;
	typedef std::list<shared_ptr<::hilti::Module>>    hilti_module_list;

	::hilti::Options hilti_options;
	::binpac::Options pac2_options;

	bool compile_all;	// Compile all event code, even if no handler, set from BifConst::Pac2::compile_all.
	bool dump_debug;	// Output debug summary, set from BifConst::Pac2::dump_debug.
	bool dump_code;		// Output generated code, set from BifConst::Pac2::dump_code.
	bool dump_code_all;	// Output all code, set from BifConst::Pac2::dump_code_all.
	bool dump_code_pre_finalize;	// Output generated code before finalizing the module, set from BifConst::Pac2::dump_code_pre_finalize.
	bool save_pac2;		// Saves all generated BinPAC++ modules into a file, set from BifConst::Pac2::save_pac2.
	bool save_hilti;	// Saves all HILTI modules into a file, set from BifConst::Pac2::save_hilti.
	bool save_llvm;		// Saves the final linked LLVM code into a file, set from BifConst::Pac2::save_llvm.

	std::list<string> import_paths;
	Pac2AST* pac2_ast;

	pac2_module_list pac2_modules;			// All loaded modules. Indexed by their paths.
	pac2_event_list  pac2_events;			// All events found in the *.evt files.
	pac2_analyzer_list pac2_analyzers;		// All analyzers found in the *.evt files.
	pac2_analyzer_vector pac2_analyzers_by_subtype;	// All analyzers indexed by their AnalyzerTag subtype.

	// The generated raise() module.
	shared_ptr<::hilti::CompilerContext>         hilti_context = nullptr; // Context for the raise() function module.
	shared_ptr<::hilti::builder::ModuleBuilder>  hilti_mbuilder = nullptr; // The HILTI moduled builder ised fpr compilation.
	shared_ptr<::hilti::Module>                  hilti_module = nullptr; // The HILTI module builder ised fpr compilation.

	// The generated hook module.
	shared_ptr<::binpac::CompilerContext>        pac2_context = nullptr;
	shared_ptr<::binpac::Module>                 pac2_module = nullptr;
	shared_ptr<::hilti::Module>                  pac2_hilti_module = nullptr;

	hilti_module_list hilti_modules;        // All HILTI modules (loaded and compiled).

	shared_ptr<TypeConverter> type_converter;
	shared_ptr<ValueConverter> value_converter;
	};

Loader::Loader()
	{
	std::set<string> cg_debug;

	for ( auto t : ::util::strsplit(BifConst::Pac2::cg_debug->CheckString(), ":") )
		cg_debug.insert(t);

	pimpl = new PIMPL;
	pimpl->pac2_ast = new Pac2AST;
	pimpl->compile_all = BifConst::Pac2::compile_all;
	pimpl->dump_debug = BifConst::Pac2::dump_debug;
	pimpl->dump_code = BifConst::Pac2::dump_code;
	pimpl->dump_code_pre_finalize = BifConst::Pac2::dump_code_pre_finalize;
	pimpl->dump_code_all = BifConst::Pac2::dump_code_all;
	pimpl->type_converter = std::make_shared<TypeConverter>();
	pimpl->save_pac2 = BifConst::Pac2::save_pac2;
	pimpl->save_hilti = BifConst::Pac2::save_hilti;
	pimpl->save_llvm = BifConst::Pac2::save_llvm;

	pimpl->hilti_options.debug = BifConst::Pac2::debug;
	pimpl->hilti_options.optimize = BifConst::Pac2::optimize;
	pimpl->hilti_options.verify = ! BifConst::Pac2::no_verify;
	pimpl->hilti_options.cg_debug = cg_debug;
	pimpl->hilti_options.module_cache = BifConst::Pac2::use_cache ? ".cache" : "";

	pimpl->pac2_options.debug = BifConst::Pac2::debug;
	pimpl->pac2_options.optimize = BifConst::Pac2::optimize;
	pimpl->pac2_options.verify = ! BifConst::Pac2::no_verify;
	pimpl->pac2_options.cg_debug = cg_debug;
	pimpl->pac2_options.module_cache = BifConst::Pac2::use_cache ? ".cache" : "";

	::hilti::init();
	::binpac::init();

	hlt_config cfg = *hlt_config_get();
	cfg.fiber_stack_size = 10 * 1024;;
	hlt_config_set(&cfg);
	}

void Loader::AddLibraryPath(const char* dirs)
	{
	for ( auto dir : ::util::strsplit(dirs, ":") )
		pimpl->import_paths.push_back(dir);
	}

Loader::~Loader()
	{
	delete pimpl->pac2_ast;
	delete pimpl;
	}

bool Loader::Load()
	{
	for ( auto dir : pimpl->import_paths )
		{
		pimpl->hilti_options.libdirs_hlt.push_back(dir);
		pimpl->pac2_options.libdirs_hlt.push_back(dir);
		pimpl->pac2_options.libdirs_pac2.push_back(dir);
		}

	pimpl->hilti_context = std::make_shared<::hilti::CompilerContext>(pimpl->hilti_options);
	pimpl->pac2_context = std::make_shared<::binpac::CompilerContext>(pimpl->pac2_options);

	pimpl->pac2_module = std::make_shared<::binpac::Module>(pimpl->pac2_context.get(), std::make_shared<::binpac::ID>("BroHooks"));

	pimpl->hilti_mbuilder = std::make_shared<::hilti::builder::ModuleBuilder>(pimpl->hilti_context, "BroFuncs");
	pimpl->hilti_module = pimpl->hilti_mbuilder->module();
	pimpl->hilti_mbuilder->importModule("Hilti");
	pimpl->hilti_mbuilder->importModule("LibBro");
	pimpl->value_converter = std::make_shared<ValueConverter>(pimpl->hilti_mbuilder);

	if ( ! SearchFiles("pac2", [&](std::istream& in, const string& path) -> bool { return LoadPac2Module(in, path); }) )
		return false;

	if ( ! SearchFiles("evt", [&](std::istream& in, const string& path) -> bool { return LoadPac2Events(in, path); }) )
		return false;

	return true;
	}

bool Loader::SearchFiles(const char* ext, std::function<bool (std::istream& in, const string& path)> const & callback)
	{
	for ( auto dir : pimpl->import_paths )
		{
		glob_t g;
		string p = dir + "/*." + ext;

		DBG_LOG(DBG_PAC2, "searching %s", p.c_str());

		if ( glob(p.c_str(), 0, 0, &g) < 0 )
			continue;

		for ( int i = 0; i < g.gl_pathc; i++ )
			{
			string path = g.gl_pathv[i];

			std::ifstream in(path);

			if ( ! in )
				{
				reporter::error(::util::fmt("Cannot open %s", path));
				return false;
				}

			if ( ! callback(in, path) )
				return false;
			}
		}

	return true;
	}

bool Loader::Compile()
	{
	// Compile all the *.pac2 modules we have loaded directly.
	for ( auto m : pimpl->pac2_modules )
		{
		auto hltmod = m->context->compile(m->module);

		if ( ! hltmod )
			return false;

		pimpl->hilti_modules.push_back(hltmod);
		}

	// Finalize and compile the pac2 module with the event hooks.

	for ( auto ev : pimpl->pac2_events )
		{
		if ( ! ev->bro_event_handler && ! pimpl->compile_all )
			// No handler for this event defined.
			continue;

		if ( ! CreatePac2Hook(ev.get()) )
			return false;
		}

	if ( pimpl->pac2_module )
		{
		if ( pimpl->dump_code_pre_finalize )
			{
			std::cerr << ::util::fmt("\n=== Pre-finalize AST: %s.pac2\n", pimpl->pac2_module->id()->name()) << std::endl;
			pimpl->pac2_context->dump(pimpl->pac2_module, std::cerr);
			std::cerr << ::util::fmt("\n=== Pre-finalize code: %s.pac2\n", pimpl->pac2_module->id()->name()) << std::endl;
			pimpl->pac2_context->print(pimpl->pac2_module, std::cerr);
			}

		if ( ! pimpl->pac2_context->finalize(pimpl->pac2_module) )
			return false;

		if ( pimpl->dump_code_pre_finalize )
			{
			std::cerr << ::util::fmt("\n=== Post-finalize, pre-compile AST: %s.pac2\n", pimpl->pac2_module->id()->name()) << std::endl;
			pimpl->pac2_context->dump(pimpl->pac2_module, std::cerr);
			std::cerr << ::util::fmt("\n=== Post-finalize, pre-compile code: %s.pac2\n", pimpl->pac2_module->id()->name()) << std::endl;
			pimpl->pac2_context->print(pimpl->pac2_module, std::cerr);
			}

		auto hltmod = pimpl->pac2_context->compile(pimpl->pac2_module);

		if ( ! hltmod )
			return false;

		pimpl->pac2_hilti_module = hltmod;
		pimpl->hilti_modules.push_back(hltmod);

		if ( pimpl->save_pac2 )
			{
			ofstream out(::util::fmt("bro.%s.pac2", pimpl->pac2_module->id()->name()));
			pimpl->pac2_context->print(pimpl->pac2_module, out);
			out.close();
			}

		}

	// Build the HILTI module with raise() functions.

	for ( auto ev : pimpl->pac2_events )
		{
		AddHiltiTypesForEvent(ev);

		if ( ! ev->bro_event_handler && ! pimpl->compile_all )
			// No handler for this event defined.
			continue;

		if ( ! CreateHiltiEventFunction(ev.get()) )
			return false;
		}

	if ( pimpl->hilti_module )
		{
		if ( pimpl->dump_code_pre_finalize )
			{
			std::cerr << ::util::fmt("\n=== Pre-finalize AST: %s.hlt\n", pimpl->hilti_module->id()->name()) << std::endl;
			pimpl->hilti_context->dump(pimpl->hilti_module, std::cerr);
			std::cerr << ::util::fmt("\n=== Pre-finalize code: %s.hlt\n", pimpl->hilti_module->id()->name()) << std::endl;
			pimpl->hilti_context->print(pimpl->hilti_module, std::cerr);
			}

		// Finalize the HILTI module.
		if ( ! pimpl->hilti_context->finalize(pimpl->hilti_module) )
			return false;

		pimpl->hilti_modules.push_back(pimpl->hilti_module);
		}

	auto hilti_context = pimpl->pac2_context->hiltiContext();

	if ( pimpl->save_hilti )
		{
		for ( auto m : pimpl->hilti_modules )
			{
			ofstream out(::util::fmt("bro.%s.hlt", m->id()->name()));
			hilti_context->print(m, out);
			out.close();
			}
		}

	// Add the standard LibBro module.

	auto libbro_path = hilti_context->searchModule(::hilti::builder::id::node("LibBro"));

	if ( ! libbro_path.size() )
		{
		reporter::error("LibBro library module not found");
		return false;
		}

	DBG_LOG(DBG_PAC2, "loading %s", libbro_path.c_str());

	auto libbro = hilti_context->loadModule(libbro_path);

	if ( ! libbro )
		{
		reporter::error("loading LibBro library module failed");
		return false;
		}

	pimpl->hilti_modules.push_back(libbro);

	// Now compile and link all the HILTI modules into LLVM. We use the
	// BinPAC++ context here to make sure we gets its additional
	// libraries linked.

	DBG_LOG(DBG_PAC2, "compiling & linking all HILTI code into a single LLVM module");

	auto llvm_module = pimpl->pac2_context->linkModules("<all Bro JIT code>", pimpl->hilti_modules, false);

	if ( ! llvm_module )
		{
		reporter::error("linking failed");
		return false;
		}

	if ( pimpl->save_llvm )
		{
		ofstream out("bro.ll");
		hilti_context->printBitcode(llvm_module, out);
		out.close();
		}

	DBG_LOG(DBG_PAC2, "running JIT on LLVM module");

	// Now JIT it into native code.
	auto ee = hilti_context->jitModule(llvm_module);

	if ( ! ee )
		{
		reporter::error("jit failed");
		return false;
		}

	extern const ::hilti::CompilerContext::FunctionMapping libbro_function_table[];
	hilti_context->installFunctionTable(libbro_function_table);

	DBG_LOG(DBG_PAC2, "initializing HILTI runtime");

	hlt_init_jit(hilti_context, llvm_module, ee);

	DBG_LOG(DBG_PAC2, "retrieving binpac_parsers() function");

	typedef hlt_list* (*binpac_parsers_func)(hlt_exception** excpt, hlt_execution_context* ctx);
	auto binpac_parsers = (binpac_parsers_func)hilti_context->nativeFunction(llvm_module, ee, "binpac_parsers");

	if ( ! binpac_parsers )
		{
		reporter::error("no function binpac_parsers()");
		return false;
		}

	DBG_LOG(DBG_PAC2, "calling binpac_parsers() function");

	hlt_exception* excpt = 0;
	hlt_execution_context* ctx = hlt_global_execution_context();

	hlt_list* parsers = (*binpac_parsers)(&excpt, ctx);

	// Record them with our analyzers.
	ExtractParsers(parsers);

	// Done, print out debug summary if requested.

	if ( pimpl->dump_debug )
		DumpDebug();

	if ( pimpl->dump_code || pimpl->dump_code_all )
		DumpCode(pimpl->dump_code_all);

	return true;
	}

bool Loader::LoadPac2Module(std::istream& in, const string& path)
	{
	DBG_LOG(DBG_PAC2, "loading units from %s", path.c_str());

	// ctx->enableDebug(dbg_scanner, dbg_parser, dbg_scopes, dbg_grammars);

	reporter::push_location(path, 0);
	auto ctx = std::make_shared<::binpac::CompilerContext>(pimpl->pac2_options);
	auto module = ctx->load(path);
	reporter::pop_location();

	if ( ! module )
		{
		reporter::error(::util::fmt("Error reading %s", path));
		return false;
		}

	pimpl->pac2_ast->process(module);

	auto minfo = std::make_shared<Pac2ModuleInfo>();
	minfo->path = path;
	minfo->context = ctx;
	minfo->module = module;
	pimpl->pac2_modules.push_back(minfo);

	return true;
	}

static void eat_spaces(const string& chunk, size_t* i)
	{
	while ( *i < chunk.size() && isspace(chunk[*i]) )
		++*i;
	}

static bool is_id_char(const string& chunk, size_t i)
	{
	char c = chunk[i];

	if ( isalnum(c) )
		return true;

	if ( strchr("_$%", c) != 0 )
		return true;

	char prev = (i > 0) ? chunk[i-1] : '\0';
	char next = (i + 1 < chunk.size()) ? chunk[i+1] : '\0';

	if ( c == ':' && next == ':' )
		return true;

	if ( c == ':' && prev == ':' )
		return true;

	return false;
	}

static bool extract_id(const string& chunk, size_t* i, string* id)
	{
	eat_spaces(chunk, i);

	size_t j = *i;

	while ( j < chunk.size() && is_id_char(chunk, j) )
		++j;

	if ( *i == j )
		goto error;

	*id = chunk.substr(*i, j - *i);
	*i = j;

	return true;

error:
	reporter::error(::util::fmt("expected id"));
	return false;

	}

// TODO: Not used anymore currently.
static bool extract_dotted_id(const string& chunk, size_t* i, string* id)
	{
	eat_spaces(chunk, i);

	size_t j = *i;

	while ( j < chunk.size() && (is_id_char(chunk, j) || chunk[j] == '.') )
		++j;

	if ( *i == j )
		goto error;

	*id = chunk.substr(*i, j - *i);
	*i = j;

	return true;

error:
	reporter::error(::util::fmt("expected dotted id"));
	return false;

	}

static bool extract_expr(const string& chunk, size_t* i, string* expr)
	{
	eat_spaces(chunk, i);

	int level = 0;
	bool done = 0;
	size_t j = *i;

	while ( j < chunk.size() )
		{
		switch ( chunk[j] ) {
		case '(':
		case '[':
		case '{':
			++level;
			++j;
			continue;

		case ')':
			if ( level == 0 )
				{
				done = true;
				break;
				}

			// fall-through

		case ']':
		case '}':
			if ( level == 0 )
				goto error;

			--level;
			++j;
			continue;

		case ',':
			if ( level == 0 )
				{
				done = true;
				break;
				}

		     // fall-through

		default:
			++j;
		}

		if ( done )
			break;

		if ( *i == j )
			break;
		}

	*expr = ::util::strtrim(chunk.substr(*i, j - *i));
	*i = j;

	return true;

error:
	reporter::error(::util::fmt("expected BinPAC++ expression"));
	return false;

	}

static string::size_type looking_at(const string& chunk, string::size_type i, const char* token)
	{
	eat_spaces(chunk, &i);

	for ( string::size_type j = 0; j < strlen(token); ++j )
		{
		if ( i >= chunk.size() || chunk[i++] != token[j] )
			return 0;
		}

	return i;
	}

static bool eat_token(const string& chunk, string::size_type* i, const char* token)
	{
	eat_spaces(chunk, i);

	auto j = looking_at(chunk, *i, token);

	if ( ! j )
		{
		reporter::error(::util::fmt("expected token '%s'", token));
		return false;
		}

	*i = j;
	return true;
	}

static bool extract_port(const string& chunk, size_t* i, Port* port)
	{
	eat_spaces(chunk, i);

	string s;
	size_t j = *i;

	while ( j < chunk.size() && isdigit(chunk[j]) )
		++j;

	if ( *i == j )
		goto error;

	s = chunk.substr(*i, j - *i);
	::util::atoi_n(s.begin(), s.end(), 10, &port->port);

	*i = j;

	if ( chunk[*i] != '/' )
		goto error;

	(*i)++;

	if ( looking_at(chunk, *i, "tcp") )
		{
		port->proto = TRANSPORT_TCP;
		eat_token(chunk, i, "tcp");
		}

	else if ( looking_at(chunk, *i, "udp") )
		{
		port->proto = TRANSPORT_UDP;
		eat_token(chunk, i, "udp");
		}

	else if ( looking_at(chunk, *i, "icmp") )
		{
		port->proto = TRANSPORT_ICMP;
		eat_token(chunk, i, "icmp");
		}

	else
		goto error;

	return true;

error:
	reporter::error(::util::fmt("cannot parse expected port specification"));
	return false;
	}

bool Loader::LoadPac2Events(std::istream& in, const string& path)
	{
	DBG_LOG(DBG_PAC2, "loading events from %s", path.c_str());

	int lineno = 0;
	string chunk;

	while ( ! in.eof() )
		{
		reporter::push_location(path, ++lineno);

		string line;
		std::getline(in, line);

		// Skip comments and empty lines.
		auto i = line.find_first_not_of(" \t");
		if ( i == string::npos )
			goto next_line;

		if ( line[i] == '#' )
			goto next_line;

		if ( chunk.size() )
			chunk += " ";

		chunk += line.substr(i, string::npos);

		// See if we have a semicolon-terminated chunk now.
		i = line.find_last_not_of(" \t");
		if ( i == string::npos )
			i = line.size() - 1;

		if ( line[i] != ';' )
			// Nope, keep adding.
			goto next_line;

		// Got it, parse the chunk.

		chunk = ::util::strtrim(chunk);

		if ( looking_at(chunk, 0, "analyzer") )
			{
			auto a = ParsePac2AnalyzerSpec(chunk);

			if ( ! a )
				goto error;

			pimpl->pac2_analyzers.push_back(a);
			RegisterBroAnalyzer(a);
			DBG_LOG(DBG_PAC2, "finished processing analyzer definition for %s", a->name.c_str());
			}

		else if ( looking_at(chunk, 0, "on") )
			{
			auto ev = ParsePac2EventSpec(chunk);

			if ( ! ev )
				goto error;

			DBG_LOG(DBG_PAC2, "finished processing event definition for %s", ev->name.c_str());
			pimpl->pac2_events.push_back(ev);
			}

		else
			reporter::error("expected 'analyzer' or 'on'");

		chunk = "";

next_line:
		reporter::pop_location();
		continue;

error:
		reporter::pop_location();
		return false;
		}

	if ( chunk.size() )
		{
		reporter::error("unterminated line at end of file");
		return false;
		}

	return true;
	}

shared_ptr<Pac2AnalyzerInfo> Loader::ParsePac2AnalyzerSpec(const string& chunk)
	{
	auto a = std::make_shared<Pac2AnalyzerInfo>();
	a->location = reporter::current_location();
	a->parser_orig = 0;
	a->parser_resp = 0;

	size_t i = 0;

	if ( ! eat_token(chunk, &i, "analyzer") )
		return 0;

	if ( ! extract_id(chunk, &i, &a->name) )
		return 0;

	if ( ! eat_token(chunk, &i, "over") )
		return 0;

	string proto;

	if ( ! extract_id(chunk, &i, &proto) )
		return 0;

	proto = ::util::strtolower(proto);

	if ( proto == "tcp" )
		a->proto = TRANSPORT_TCP;

	else if ( proto == "udp" )
		a->proto = TRANSPORT_UDP;

	else if ( proto == "icmp" )
		a->proto = TRANSPORT_ICMP;

	else
		{
		reporter::error(::util::fmt("unknown transport protocol '%s'", proto));
		return 0;
		}

	if ( ! eat_token(chunk, &i, ":") )
		return 0;

	enum { orig, resp, both } dir;

	while ( true )
		{
		if ( looking_at(chunk, i, "parse") )
			{
			eat_token(chunk, &i, "parse");

			if ( looking_at(chunk, i, "originator") )
				{
				eat_token(chunk, &i, "originator");
				dir = orig;
				}

			else if ( looking_at(chunk, i, "responder") )
				{
				eat_token(chunk, &i, "responder");
				dir = resp;
				}

			else if ( looking_at(chunk, i, "with") )
				dir = both;

			else
				{
				reporter::error("invalid parse-with specification");
				return 0;
				}

			if ( ! eat_token(chunk, &i, "with") )
				return 0;

			string unit;

			if ( ! extract_id(chunk, &i, &unit) )
				return 0;

			switch ( dir )	{
			case orig:
				a->unit_name_orig = unit;
				break;

			case resp:
				a->unit_name_resp = unit;
				break;

			case both:
				a->unit_name_orig = unit;
				a->unit_name_resp = unit;
				break;
			}

			if ( a->unit_name_orig.size() )
				{
				a->unit_orig = pimpl->pac2_ast->LookupUnit(a->unit_name_orig);

				if ( ! a->unit_orig )
					{
					reporter::error(::util::fmt("unknown unit type %s with analyzer %s", a->unit_name_orig, a->name));
					return 0;
					}
				}

			if ( a->unit_name_resp.size() )
				{
				a->unit_resp = pimpl->pac2_ast->LookupUnit(a->unit_name_resp);

				if ( ! a->unit_resp )
					{
					reporter::error(::util::fmt("unknown unit type with analyzer %s", a->unit_name_resp, a->name));
					return 0;
					}
				}
			}

		else if ( looking_at(chunk, i, "ports") )
			{
			eat_token(chunk, &i, "ports");

			if ( ! eat_token(chunk, &i, "{") )
				return 0;

			while ( true )
				{
				Port p;

				if ( ! extract_port(chunk, &i, &p) )
					return 0;

				a->ports.push_back(p);

				if ( looking_at(chunk, i, "}") )
					{
					eat_token(chunk, &i, "}");
					break;
					}

				if ( ! eat_token(chunk, &i, ",") )
					return 0;
				}
			}

		else if ( looking_at(chunk, i, "port") )
			{
			eat_token(chunk, &i, "port");

			Port p;

			if ( ! extract_port(chunk, &i, &p) )
				return 0;

			a->ports.push_back(p);
			}

		if ( looking_at(chunk, i, ";") )
			break; // All done.

		if ( ! eat_token(chunk, &i, ",") )
			return 0;
		}

	return a;
	}

shared_ptr<Pac2EventInfo> Loader::ParsePac2EventSpec(const string& chunk)
	{
	auto ev = std::make_shared<Pac2EventInfo>();

	std::list<string> exprs;

	string path;
	string name;
	string expr;

	size_t i = 0;

	if ( ! eat_token(chunk, &i, "on") )
		return 0;

	if ( ! extract_id(chunk, &i, &path) )
		return 0;

	if ( ! eat_token(chunk, &i, "->") )
		return 0;

	if ( ! eat_token(chunk, &i, "event") )
		return 0;

	if ( ! extract_id(chunk, &i, &name) )
		return 0;

	if ( ! eat_token(chunk, &i, "(") )
		return 0;

	bool first = true;
	size_t j = 0;

	while ( true )
		{
		j = looking_at(chunk, i, ")");

		if ( j )
			{
			i = j;
			break;
			}

		if ( ! first )
			{
			if ( ! eat_token(chunk, &i, ",") )
				return 0;
			}

		if ( ! extract_expr(chunk, &i, &expr) )
			return 0;

		exprs.push_back(expr);
		first = false;
		}

	if ( ! eat_token(chunk, &i, ";") )
		return 0;

	eat_spaces(chunk, &i);

	if ( i < chunk.size() )
		{
		// This shouldn't actually be possible ...
		reporter::error("unexpected characters at end of line");
		return 0;
		}

	// If we find the path directly, it's a unit type; then add a "%done"
	// to form the hook name.
	string hook;
	string hook_local;
	string unit;
	auto unit_type = pimpl->pac2_ast->LookupUnit(path);

	if ( unit_type )
		{
		hook += path + "::%done";
		hook_local = "%done";
		unit = path;
		}

	else
		{
		// Strip the last element of the path, the remainder must
		// refer to a unit.
		auto p = ::util::strsplit(path, "::");
		if ( p.size() )
			{
			hook_local = p.back();
			p.pop_back();
			unit = ::util::strjoin(p, "::");
			unit_type = pimpl->pac2_ast->LookupUnit(unit);
			hook = path;
			}
		}

	if ( ! unit_type )
		{
		reporter::error(::util::fmt("unknown unit type in %s", hook));
		return 0;
		}

	ev->name = name;
	ev->exprs = exprs;
	ev->hook = hook;
	ev->hook_local = hook_local;
	ev->location = reporter::current_location();
	ev->unit = unit;
	ev->unit_type = unit_type;
	ev->unit_module = unit_type->firstParent<::binpac::Module>();
	assert(ev->unit_module);

	if ( ! CreateExpressionAccessors(ev) )
		return 0;

	RegisterBroEvent(ev);

	return ev;
	}

void Loader::RegisterBroAnalyzer(shared_ptr<Pac2AnalyzerInfo> a)
	{
	AnalyzerTag::MainType mtype = AnalyzerTag::Error;
	analyzer_config_factory_callback factory = 0;
	analyzer_config_available_callback available = 0;

	switch ( a->proto ) {
	case TRANSPORT_TCP:
		mtype = AnalyzerTag::PAC2_TCP;
		factory = Pac2_TCP_Analyzer::InstantiateAnalyzer;
		available = Pac2_TCP_Analyzer::Available;
		break;

	case TRANSPORT_UDP:
		mtype = AnalyzerTag::PAC2_UDP;
		factory = Pac2_UDP_Analyzer::InstantiateAnalyzer;
		available = Pac2_UDP_Analyzer::Available;
		break;

	default:
		reporter::error("unsupported protocol in analyzer");
		return;
	}

	a->subtype = pimpl->pac2_analyzers_by_subtype.size();
	pimpl->pac2_analyzers_by_subtype.push_back(a);

	auto tag = AnalyzerTag(mtype, a->subtype);

	dpm->AddAnalyzer(tag,
			 a->name.c_str(),
			 factory,
			 available,
			 0,
			 false);

	for ( auto p : a->ports )
		dpm->RegisterAnalyzerForPort(tag, p.proto, p.port);

	}

void Loader::RegisterBroEvent(shared_ptr<Pac2EventInfo> ev)
	{
	type_decl_list* types = new type_decl_list();

	for ( auto e : ev->expr_accessors )
		{
		BroType* t = nullptr;

		if ( e->expr == "$conn" )
			{
			t = connection_type;
			Ref(t);
			types->append(new TypeDecl(t, strdup("c")));
			}

		else if ( e->expr == "$is_orig" )
			types->append(new TypeDecl(base_type(TYPE_BOOL), strdup("is_orig")));

		else
			{
			auto p = util::fmt("arg%d", e->nr);
			BroType* t = pimpl->type_converter->Convert(e->htype, e->btype);
			types->append(new TypeDecl(t, strdup(p.c_str())));
			}
		}

	auto ftype = new FuncType(new RecordType(types), 0, FUNC_FLAVOR_EVENT);
	ev->bro_event_type = ftype;

	EventHandlerPtr handler = event_registry->Lookup(ev->name.c_str());

	if ( handler )
		{
		if ( handler->LocalHandler() )
			{
			// To enable scoped event names, export their IDs
			// implicitly.
			auto id = global_scope()->Lookup(handler->LocalHandler()->Name());
			if ( id )
				id->SetExport();
			}

		if ( handler->FType() && ! same_type(ftype, handler->FType()) )
			{
			ODesc have;
			ODesc want;
			handler->FType()->Describe(&have);
			ftype->Describe(&want);

			auto l = handler->FType()->GetLocationInfo();
			reporter::__push_location(l->filename, l->first_line);
			reporter::error(::util::fmt("type mismatch for event handler %s: expected %s, but got %s",
						    ev->name, want.Description(), have.Description()));
			reporter::pop_location();
			return;
			}

		ev->bro_event_handler = handler;
		}

	else
		ev->bro_event_handler = 0;

#ifdef DEBUG
	ODesc d;
	d.SetShort();
	ev->bro_event_type->Describe(&d);
	const char* handled = (ev->bro_event_handler ? "has handler" : "no handlers");
	DBG_LOG(DBG_PAC2, "new Bro event '%s: %s' (%s)", ev->name.c_str(), d.Description(), handled);
#endif
	}

static shared_ptr<::binpac::Expression> id_expr(const string& id)
	{
	return std::make_shared<::binpac::expression::ID>(std::make_shared<::binpac::ID>(id));
	}

bool Loader::CreatePac2Hook(Pac2EventInfo* ev)
	{
	DBG_LOG(DBG_PAC2, "adding pac2 hook %s for event %s", ev->hook.c_str(), ev->name.c_str());

	pimpl->pac2_module->import(ev->unit_module->id());

	::binpac::expression_list args_tuple = { id_expr("self") };
	auto args = std::make_shared<::binpac::expression::Constant>(std::make_shared<::binpac::constant::Tuple>(args_tuple));

	auto raise_name = ::util::fmt("BroFuncs::raise_%s", ::util::strreplace(ev->name, "::", "_"));
	::binpac::expression_list op_args = { id_expr(raise_name), args };
	auto call = std::make_shared<::binpac::expression::UnresolvedOperator>(::binpac::operator_::Call, op_args);
	auto stmt = std::make_shared<::binpac::statement::Expression>(call);
	auto body = std::make_shared<::binpac::statement::Block>(pimpl->pac2_module->body()->scope());

	body->addStatement(stmt);

	auto hook = std::make_shared<::binpac::Hook>(body);
	auto hdecl = std::make_shared<::binpac::declaration::Hook>(std::make_shared<::binpac::ID>(ev->hook), hook);

	auto raise_result = std::make_shared<::binpac::type::function::Result>(std::make_shared<::binpac::type::Void>(), true);
	::binpac::parameter_list raise_params = {
		std::make_shared<::binpac::type::function::Parameter>(std::make_shared<::binpac::ID>("self"),
								      std::make_shared<::binpac::type::Unknown>(std::make_shared<::binpac::ID>(ev->unit)),
								      true, false, nullptr),
	};

	auto raise_type = std::make_shared<::binpac::type::Function>(raise_result, raise_params, ::binpac::type::function::BINPAC_HILTI);
	auto raise_func = std::make_shared<::binpac::Function>(std::make_shared<::binpac::ID>(raise_name), raise_type, pimpl->pac2_module);
	auto rdecl = std::make_shared<::binpac::declaration::Function>(raise_func, ::binpac::Declaration::IMPORTED);

	pimpl->pac2_module->body()->addDeclaration(hdecl);
	pimpl->pac2_module->body()->addDeclaration(rdecl);

	ev->pac2_hook = hdecl;

	return true;
	}

bool Loader::CreateExpressionAccessors(shared_ptr<Pac2EventInfo> ev)
	{
	int nr = 0;

	for ( auto e : ev->exprs )
		{
		auto acc = std::make_shared<Pac2ExpressionAccessor>();
		acc->nr = ++nr;
		acc->expr = e;
		acc->dollar_id = util::startsWith(e, "$");

		if ( ! acc->dollar_id )
			// We set the other fields below in a second loop.
			acc->pac2_func = CreatePac2ExpressionAccessor(ev, acc->nr, e);

		else
			{
			if ( e != "$conn" && e != "$is_orig" )
				{
				reporter::error(::util::fmt("unsupported parameters %s", e));
				return false;
				}
			}

		ev->expr_accessors.push_back(acc);
		}

	// Resolve the code as far possible.
	pimpl->pac2_module->import(ev->unit_module->id());
	pimpl->pac2_context->partialFinalize(pimpl->pac2_module);

	for ( auto acc : ev->expr_accessors )
		{
		if ( acc->dollar_id )
			continue;

		acc->btype = acc->pac2_func ? acc->pac2_func->function()->type()->result()->type() : nullptr;
		acc->htype = acc->btype ? pimpl->pac2_context->hiltiType(acc->btype) : nullptr;
		acc->hlt_func = DeclareHiltiExpressionAccessor(ev, acc->nr, acc->htype);
		}

	return true;
	}

shared_ptr<binpac::declaration::Function> Loader::CreatePac2ExpressionAccessor(shared_ptr<Pac2EventInfo> ev, int nr, const string& expr)
	{
	auto fname = ::util::fmt("accessor_%s_arg%d", ::util::strreplace(ev->name, "::", "_"), nr);

	DBG_LOG(DBG_PAC2, "defining BinPAC++ function %s for parameter %d of event %s", fname.c_str(), nr, ev->name.c_str());

	auto pac2_expr = pimpl->pac2_context->parseExpression(expr);

	if ( ! pac2_expr )
		{
		reporter::error(::util::fmt("error parsing expression '%s'", expr));
		return nullptr;
		}

	auto stmt = std::make_shared<::binpac::statement::Return>(pac2_expr);
	auto body = std::make_shared<::binpac::statement::Block>(pimpl->pac2_module->body()->scope());
	body->addStatement(stmt);

	auto unknown = std::make_shared<::binpac::type::Unknown>();
	auto func_result = std::make_shared<::binpac::type::function::Result>(unknown, true);
	::binpac::parameter_list func_params = {
		std::make_shared<::binpac::type::function::Parameter>(std::make_shared<::binpac::ID>("self"),
								      std::make_shared<::binpac::type::Unknown>(std::make_shared<::binpac::ID>(ev->unit)),
								      true, false, nullptr),
	};

	auto ftype = std::make_shared<::binpac::type::Function>(func_result, func_params, ::binpac::type::function::HILTI);
	auto func = std::make_shared<::binpac::Function>(std::make_shared<::binpac::ID>(fname), ftype, pimpl->pac2_module, body);
	auto fdecl = std::make_shared<::binpac::declaration::Function>(func, ::binpac::Declaration::EXPORTED);

	pimpl->pac2_module->body()->addDeclaration(fdecl);

	return fdecl;
	}


shared_ptr<::hilti::declaration::Function> Loader::DeclareHiltiExpressionAccessor(shared_ptr<Pac2EventInfo> ev, int nr, shared_ptr<::hilti::Type> rtype)
	{
	auto fname = ::util::fmt("BroHooks::accessor_%s_arg%d", ::util::strreplace(ev->name, "::", "_"), nr);

	DBG_LOG(DBG_PAC2, "declaring HILTI function %s for parameter %d of event %s", fname.c_str(), nr, ev->name.c_str());

	auto result = ::hilti::builder::function::result(rtype);

	::hilti::builder::function::parameter_list args = {
		::hilti::builder::function::parameter("self", ::hilti::builder::reference::type(::hilti::builder::type::byName(ev->unit)), true, nullptr),
		};

	auto func = ModuleBuilder()->declareFunction(fname, result, args);
	ModuleBuilder()->exportID(fname);

	return func;
	}

void Loader::AddHiltiTypesForEvent(shared_ptr<Pac2EventInfo> ev)
	{
	auto uid = ::hilti::builder::id::node(ev->unit);

	if ( ModuleBuilder()->declared(uid) )
		return;

	auto t = pimpl->pac2_hilti_module->body()->scope()->lookup(uid, true);
	assert(t.size() == 1);

	auto unit_type = ast::checkedCast<::hilti::expression::Type>(t.front())->typeValue();
	pimpl->hilti_mbuilder->addType(ev->unit, unit_type);
	}

bool Loader::CreateHiltiEventFunction(Pac2EventInfo* ev)
	{
	string fname = ::util::fmt("raise_%s", ::util::strreplace(ev->name, "::", "_"));

	DBG_LOG(DBG_PAC2, "adding HILTI function %s for event %s", fname.c_str(), ev->name.c_str());

	auto result = ::hilti::builder::function::result(::hilti::builder::void_::type());

	::hilti::builder::function::parameter_list args = {
		::hilti::builder::function::parameter("self", ::hilti::builder::reference::type(::hilti::builder::type::byName(ev->unit)), true, nullptr),
		::hilti::builder::function::parameter("cookie", ::hilti::builder::type::byName("LibBro::Cookie"), true, nullptr)
		};

	auto func = ModuleBuilder()->pushFunction(fname, result, args);
	ModuleBuilder()->exportID(fname);

	::hilti::builder::tuple::element_list vals;

	for ( auto e : ev->expr_accessors )
		{
		auto val = ModuleBuilder()->addTmp("val", ::hilti::builder::type::byName("LibBro::BroVal"));

		if ( e->expr == "$conn" )
			{
			Builder()->addInstruction(val,
						  ::hilti::instruction::flow::CallResult,
						  ::hilti::builder::id::create("LibBro::cookie_to_conn_val"),
						  ::hilti::builder::tuple::create( { ::hilti::builder::id::create("cookie") } ));
			}

		else if ( e->expr == "$is_orig" )
			{
			Builder()->addInstruction(val,
						  ::hilti::instruction::flow::CallResult,
						  ::hilti::builder::id::create("LibBro::cookie_to_is_orig"),
						  ::hilti::builder::tuple::create( { ::hilti::builder::id::create("cookie") } ));
			}

		else
			{
			auto tmp = ModuleBuilder()->addTmp("t", e->htype);
			auto func_id = e->hlt_func ? e->hlt_func->id() : ::hilti::builder::id::node("null-function>");

			Builder()->addInstruction(tmp,
						  ::hilti::instruction::flow::CallResult,
						  ::hilti::builder::id::create(func_id),
						  ::hilti::builder::tuple::create( { ::hilti::builder::id::create("self") } ));

			pimpl->value_converter->Convert(tmp, val, e->btype);
			}

		vals.push_back(val);
		}

	Builder()->addInstruction(::hilti::instruction::flow::CallVoid,
				  ::hilti::builder::id::create("LibBro::raise_event"),
				  ::hilti::builder::tuple::create({ ::hilti::builder::bytes::create(ev->name),
				                                    ::hilti::builder::tuple::create(vals) } ));

	ModuleBuilder()->popFunction();

	ev->hilti_raise = func;

	return true;
	}

::hilti::builder::BlockBuilder* Loader::Builder() const
	{
	assert(pimpl->hilti_mbuilder);
	return pimpl->hilti_mbuilder->builder().get();
	}

::hilti::builder::ModuleBuilder* Loader::ModuleBuilder() const
	{
	assert(pimpl->hilti_mbuilder);
	return pimpl->hilti_mbuilder.get();
	}

void Loader::ExtractParsers(hlt_list* parsers)
	{
	hlt_exception* excpt = 0;
	hlt_execution_context* ctx = hlt_global_execution_context();

	hlt_iterator_list i = hlt_list_begin(parsers, &excpt, ctx);
	hlt_iterator_list end = hlt_list_end(parsers, &excpt, ctx);

	std::map<string, binpac_parser*> parser_map;

	while ( ! (hlt_iterator_list_eq(i, end, &excpt, ctx) || excpt) )
		{
		binpac_parser* p = *(binpac_parser**) hlt_iterator_list_deref(i, &excpt, ctx);
		char* name = hlt_string_to_native(p->name, &excpt, ctx);
		parser_map.insert(std::make_tuple(name, p));
		hlt_free(name);

		hlt_iterator_list j = i;
                i = hlt_iterator_list_incr(i, &excpt, ctx);
                GC_DTOR(j, hlt_iterator_list);
		}

	GC_DTOR(i, hlt_iterator_list);
	GC_DTOR(end, hlt_iterator_list);

	for ( auto a : pimpl->pac2_analyzers )
		{
		auto i = parser_map.find(a->unit_name_orig);

		if ( i != parser_map.end() )
			{
			a->parser_orig = i->second;
			GC_CCTOR(a->parser_orig, hlt_Parser);
			}

		i = parser_map.find(a->unit_name_resp);

		if ( i != parser_map.end() )
			{
			a->parser_resp = i->second;
			GC_CCTOR(a->parser_resp, hlt_Parser);
			}
		}

	for ( auto p : parser_map )
		{
		GC_DTOR(p.second, hlt_Parser);
		}
	}

string Loader::AnalyzerName(const AnalyzerTag& tag)
	{
	if ( tag.Type() != AnalyzerTag::PAC2_TCP && tag.Type() != AnalyzerTag::PAC2_UDP )
		return "<not a pac2 analyzer>";

	if ( tag.Subtype() >= pimpl->pac2_analyzers_by_subtype.size() )
		return "<unknown pac2 sub-analyzer>";

	return pimpl->pac2_analyzers_by_subtype[tag.Subtype()]->name;
	}

struct __binpac_parser* Loader::ParserForAnalyzer(const AnalyzerTag& tag, bool is_orig)
	{
	if ( tag.Type() != AnalyzerTag::PAC2_TCP && tag.Type() != AnalyzerTag::PAC2_UDP )
		return 0;

	if ( tag.Subtype() >= pimpl->pac2_analyzers_by_subtype.size() )
		return 0;

	if ( is_orig )
		return pimpl->pac2_analyzers_by_subtype[tag.Subtype()]->parser_orig;
	else
		return pimpl->pac2_analyzers_by_subtype[tag.Subtype()]->parser_resp;
	}

void Loader::DumpDebug()
	{
	std::cerr << "BinPAC++ analyzer summary:" << std::endl;
	std::cerr << std::endl;

	std::cerr << "  Modules" << std::endl;

	for ( PIMPL::pac2_module_list::iterator i = pimpl->pac2_modules.begin(); i != pimpl->pac2_modules.end(); i++ )
		{
		auto minfo = *i;
		std::cerr << "    " << minfo->module->id()->name() << " (from " << minfo->path << ")" << std::endl;
		}

	std::cerr << std::endl;

	std::cerr << "  Analyzers" << std::endl;

	string location;				// Location where the analyzer was defined.
	string name;					// Name of the analyzer.
	TransportProto proto;				// The transport layer the analyzer uses.
	std::list<Port> ports;				// The ports associated with the analyzer.
	string unit_name_orig;				// The fully-qualified name of the unit type to parse the originator side.
	string unit_name_resp;				// The fully-qualified name of the unit type to parse the originator side.
	shared_ptr<binpac::type::Unit> unit_orig;	// The type of the unit to parse the originator side.
	shared_ptr<binpac::type::Unit> unit_resp;	// The type of the unit to parse the originator side.

	for ( auto i = pimpl->pac2_analyzers.begin(); i != pimpl->pac2_analyzers.end(); i++ )
		{
		auto a = *i;

		string proto = transportToString(a->proto);

		std::list<string> ports;
		for ( auto p : a->ports )
			ports.push_back(p);

		std::cerr << "    " << a->name << " [" << proto << ", subtype " << a->subtype << "] [" << a->location << "]" << std::endl;
		std::cerr << "        Ports      : " << (ports.size() ? ::util::strjoin(ports, ", ") : "none") << std::endl;
		std::cerr << "        Orig parser: " << (a->unit_orig ? a->unit_orig->id()->pathAsString() : "none" ) << " ";

		string desc = "not compiled";

		if ( a->parser_orig )
			{
			assert(a->parser_orig);
			hlt_exception* excpt = 0;
			auto s = hlt_string_to_native(a->parser_orig->description, &excpt, hlt_global_execution_context());
			desc = ::util::fmt("compiled; unit description: \"%s\"", s);
			hlt_free(s);
			}

		std::cerr << "[" << desc << "]" << std::endl;

		std::cerr << "        Resp parser: " << (a->unit_resp ? a->unit_resp->id()->pathAsString() : "none" ) << " ";

		desc = "not compiled";

		if ( a->parser_resp )
			{
			assert(a->parser_resp);
			hlt_exception* excpt = 0;
			auto s = hlt_string_to_native(a->parser_resp->description, &excpt, hlt_global_execution_context());
			desc = ::util::fmt("compiled; unit description: \"%s\"", s);
			hlt_free(s);
			}

		std::cerr << "[" << desc << "]" << std::endl;

		std::cerr << std::endl;
		}

	std::cerr << "  Units" << std::endl;

	for ( Pac2AST::unit_map::const_iterator i = pimpl->pac2_ast->Units().begin(); i != pimpl->pac2_ast->Units().end(); i++ )
		{
		Pac2AST::UnitInfo uinfo = i->second;
		std::cerr << "    " << uinfo.name << std::endl;
		}

	std::cerr << std::endl;

	std::cerr << "  Events" << std::endl;

	for ( PIMPL::pac2_event_list::iterator i = pimpl->pac2_events.begin(); i != pimpl->pac2_events.end(); i++ )
		{
		auto ev = *i;

		string args;

		for ( auto e : ev->expr_accessors )
			{
			if ( args.size() )
				args += ", ";

			if ( e->btype )
				args += ::util::fmt("arg%d: %s", e->nr, e->btype->render());
			else
				args += e->expr;
			}

		std::cerr << "    * " << ev->unit << "/" << ev->hook_local << " -> " << ev->name
			  << '(' << args << ") [unit: " << ev->unit_module->id()->name() << "] "
			  << ev->location << "]"
			  << std::endl;

		std::cerr << "      - [Bro]      " << ev->name << ": ";

		if ( ev->bro_event_type )
			{
			ODesc d;
			d.SetShort();
			ev->bro_event_type->Describe(&d);
			std::cerr << d.Description()
				  << " [" << (ev->bro_event_handler ? "has handler" : "no handler") <<  "]"
				  << std::endl;
			}

		else
			std::cerr << "(not created)" << std::endl;

		std::cerr << "      - [BinPAC++] ";

		if ( ev->pac2_hook )
			{
			auto id = ev->pac2_hook->id();
			auto hook = ev->pac2_hook->hook();
			std::cerr << id->pathAsString() << std::endl;
			}
		else
			std::cerr << "(not created)" << std::endl;

		std::cerr << "      - [HILTI]    ";

		if ( ev->hilti_raise )
			{
			auto id = ev->hilti_raise->id();
			auto func = ev->hilti_raise->function();
			std::cerr << id->pathAsString() << ": " << func->type()->render() << std::endl;
			}
		else
			std::cerr << "(not created)" << std::endl;

		std::cerr << std::endl;
		}

	std::cerr << std::endl;
	}

void Loader::DumpCode(bool all)
	{
	std::cerr << ::util::fmt("\n=== Final code: %s.pac2\n", pimpl->pac2_module->id()->name()) << std::endl;

	if ( pimpl->pac2_context && pimpl->pac2_module )
		pimpl->pac2_context->print(pimpl->pac2_module, std::cerr);
	else
		std::cerr << "(No BinPAC++ code generated.)" << std::endl;

	if ( ! all )
		{
		std::cerr << ::util::fmt("\n=== Final code: %s.hlt\n", pimpl->hilti_module->id()->name()) << std::endl;

		if ( pimpl->hilti_context && pimpl->hilti_module )
			pimpl->hilti_context->print(pimpl->hilti_module, std::cerr);
		else
			std::cerr << "(No HILTI code generated.)" << std::endl;
		}

	else
		{
		for ( auto m : pimpl->hilti_modules )
			{
			std::cerr << ::util::fmt("\n=== Final code: %s.hlt\n", m->id()->name()) << std::endl;
			pimpl->hilti_context->print(m, std::cerr);
			}
		}
	}

