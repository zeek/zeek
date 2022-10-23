// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Desc.h"
#include "zeek/script_opt/CPP/Func.h"
#include "zeek/script_opt/CPP/InitsInfo.h"
#include "zeek/script_opt/CPP/Tracker.h"
#include "zeek/script_opt/CPP/Util.h"
#include "zeek/script_opt/ScriptOpt.h"

// We structure the compiler for generating C++ versions of Zeek script
// bodies maily as a single large class.  While we divide the compiler's
// functionality into a number of groups (see below), these interact with
// one another, and in particular with various member variables, enough
// so that it's not clear there's benefit to further splitting the
// functionality into multiple classes.  (Some splitting has already been done
// for more self-contained functionality, resulting in the CPPTracker class
// and initialization information in InitsInfo.{h,cc} and RuntimeInits.{h,cc}.)
//
// Most aspects of translating to C++ have a straightforward nature.
// We can turn many Zeek script statements directly into the C++ that's
// used by the interpreter for the corresponding Exec()/DoExec() methods.
// This often holds for Zeek expressions, too, though some of them require
// considerations (e.g., error handling) that require introducing helper
// functions to maintain the property that a Zeek script expression translates
// to a C++ expression.  That property (i.e., not needing to turn Zeek
// expressions into multiple C++ statements) simplifies code generation
// considerably.  It also means that the compiler should *not* run on
// transformed ASTs such as produced by the Reducer class.  We instead
// seek to let the C++ compiler (meaning clang or g++, for example)
// find optimization opportunities, including inlining.
//
// For some Zeek scripting types, we use their natural C++ counterparts,
// such as "zeek_uint_t" for "count" values.  In the source code these
// are referred to as "native" types.  Other types, like tables, keep
// their interpreter-equivalent type (e.g., TableVal).  These are dealt
// with almost entirely using IntrusivePtr's.  The few exceptions (i.e.,
// direct uses of "new") are in contexts where the memory management
// is clearly already addressed.
//
// The user specifies generation of C++ using "-O gen-C++", which produces
// C++ code for all of the loaded functions/hooks/event handlers.  Thus,
// for example, "zeek -b -O gen-C++ foo.zeek" will generate C++ code for
// all of the scripts loaded in "bare" mode, plus those for foo.zeek; and
// without the "-b" for all of the default scripts plus those in foo.zeek.
//
// "-O report-C++" reports on which compiled functions will/won't be used
// (including ones that are available but not relevant to the scripts loaded
// on the command line).  This can be useful when debugging to make sure
// that you're indeed running compiled code when you expect to be.
//
// We partition the methods of the compiler into a number of groups,
// the definitions of each having their own source file:
//
//	Driver		Drives the overall compilation process.
//
//	Vars		Management of C++ variables relating to local/global
//			script variables.
//
//	DeclFunc	Generating declarations of C++ subclasses and
//			functions.
//
//	GenFunc		Generating the bodies of script functions.
//
//	Consts		Dealing with Zeek script constants.  Depending
//			on their type, these are represented either
//			directly in C++, or using C++ variables that
//			are constructed at run-time.
//
//	Stmts		Generating code for Zeek statements.
//
//	Exprs		Generating code for Zeek expressions.
//
//	Types		Management of (1) C++ types used in generated code,
//			and (2) C++ variables that hold Zeek script types,
//			generated at run-time.
//
//	Attrs		Management of Zeek type attributes, some of which
//			must be generated at run-time.
//
//	Inits		Management of initializing the run-time
//			variables needed by the compiled code.
//
//	Emit		Low-level code generation.
//
// Of these, Inits is the most subtle and complex.  There are two major
// challenges in creating run-time values (such as Zeek types and constants).
//
// First, generating individual code for creating each of these winds up
// incurring unacceptable compile times (for example, clang compiling all
// of the base scripts with optimization takes many hours on a high-end
// laptop).  As a result, we employ a table-driven approach that compiles
// much faster (though still taking many minutes on the same high-end laptop,
// running about 40x faster however).
//
// Second, initializations frequently rely upon *other* initializations
// having occurred first.  For example, a global might need a record type
// to be defined; one of the record's fields is a table; that table contains
// another record; one of that other record's fields is the original record
// (recursion); another field has an &default expression that requires the
// compiler to generate a helper function to construct the expression
// dynamically; and that helper function might in turn refer to other types
// that require initialization.  What's required is a framework for ensuring
// that everything occurs in the proper order.
//
// The logic for dealing with these complexities is isolated into several
// sets of classes.  InitsInfo.{h,cc} provides the classes related to tracking
// how to generate initializations in the proper order.  RuntimeInits.{h,cc}
// provides the classes used when initialization generated code in order
// to instantiate all of the necessary values.  See those files for discussions
// on how they address the points framed above.
//
// In declaring the CPPCompiler class, we group methods in accordance with
// those listed above, locating member variables with the group most relevant
// for their usage.  However, keep in mind that many member variables are
// used by multiple groups, which is why we haven't created distinct
// per-group classes.  In addition, we make a number of methods public
// in order to avoid the need for numerous "friend" declarations to allow
// associated classes (like those for initialization) access to a the
// necessary compiler methods.

namespace zeek::detail
	{

class CPPCompile
	{
public:
	CPPCompile(std::vector<FuncInfo>& _funcs, ProfileFuncs& pfs, const std::string& gen_name,
	           bool add, bool _standalone, bool report_uncompilable);
	~CPPCompile();

	// Constructing a CPPCompile object does all of the compilation.
	// The public methods here are for use by helper classes.

	// Tracks the given type (with support methods for ones that
	// are complicated), recursively including its sub-types, and
	// creating initializations for constructing C++ variables
	// representing the types.
	//
	// Returns the initialization info associated with the type.
	std::shared_ptr<CPP_InitInfo> RegisterType(const TypePtr& t);

	// Easy access to the global offset and the initialization
	// cohort associated with a given type.
	int TypeOffset(const TypePtr& t) { return GI_Offset(RegisterType(t)); }
	int TypeCohort(const TypePtr& t) { return GI_Cohort(RegisterType(t)); }

	// Tracks a Zeek ValPtr used as a constant value.  These occur
	// in two contexts: directly as constant expressions, and indirectly
	// as elements within aggregate constants (such as in vector
	// initializers).
	//
	// Returns the associated initialization info.  In addition,
	// consts_offset returns an offset into an initialization-time
	// global that tracks all constructed globals, providing
	// general access to them for aggregate constants.
	std::shared_ptr<CPP_InitInfo> RegisterConstant(const ValPtr& vp, int& consts_offset);

	// Tracks a global to generate the necessary initialization.
	// Returns the associated initialization info.
	std::shared_ptr<CPP_InitInfo> RegisterGlobal(const ID* g);

	// Tracks a use of the given set of attributes, including
	// initialization dependencies and the generation of any
	// associated expressions.
	//
	// Returns the initialization info associated with the set of
	// attributes.
	std::shared_ptr<CPP_InitInfo> RegisterAttributes(const AttributesPtr& attrs);

	// Convenient access to the global offset associated with
	// a set of Attributes.
	int AttributesOffset(const AttributesPtr& attrs)
		{
		return GI_Offset(RegisterAttributes(attrs));
		}

	// The same, for a single attribute.
	std::shared_ptr<CPP_InitInfo> RegisterAttr(const AttrPtr& attr);
	int AttrOffset(const AttrPtr& attr) { return GI_Offset(RegisterAttr(attr)); }

	// Returns a mapping of from Attr objects to their associated
	// initialization information.  The Attr must have previously
	// been registered.
	auto& ProcessedAttr() const { return processed_attr; }

	// True if the given expression is simple enough that we can
	// generate code to evaluate it directly, and don't need to
	// create a separate function per RegisterInitExpr() to track it.
	static bool IsSimpleInitExpr(const ExprPtr& e);

	// Tracks expressions used in attributes (such as &default=<expr>).
	//
	// We need to generate code to evaluate these, via CallExpr's
	// that invoke functions that return the value of the expression.
	// However, we can't generate that code when first encountering
	// the attribute, because doing so will need to refer to the names
	// of types, and initially those are unavailable (because the type's
	// representatives, per pfs.RepTypes(), might not have yet been
	// tracked).  So instead we track the associated CallExprInitInfo
	// objects, and after all types have been tracked, then spin
	// through them to generate the code.
	//
	// Returns the associated initialization information.
	std::shared_ptr<CPP_InitInfo> RegisterInitExpr(const ExprPtr& e);

	// Tracks a C++ string value needed for initialization.  Returns
	// an offset into the global vector that will hold these.
	int TrackString(std::string s)
		{
		auto ts = tracked_strings.find(s);
		if ( ts != tracked_strings.end() )
			return ts->second;

		int offset = ordered_tracked_strings.size();
		tracked_strings[s] = offset;
		ordered_tracked_strings.emplace_back(s);

		return offset;
		}

	// Tracks a profile hash value needed for initialization.  Returns
	// an offset into the global vector that will hold these.
	int TrackHash(p_hash_type h)
		{
		auto th = tracked_hashes.find(h);
		if ( th != tracked_hashes.end() )
			return th->second;

		int offset = ordered_tracked_hashes.size();
		tracked_hashes[h] = offset;
		ordered_tracked_hashes.emplace_back(h);

		return offset;
		}

	// Returns the hash associated with a given function body.
	// It's a fatal error to call this for a body that hasn't
	// been compiled.
	p_hash_type BodyHash(const Stmt* body);

	// Returns true if at least one of the function bodies associated
	// with the function/hook/event handler of the given fname is
	// not compilable.
	bool NotFullyCompilable(const std::string& fname) const
		{
		return not_fully_compilable.count(fname) > 0;
		}

private:
	// Start of methods related to driving the overall compilation
	// process.
	// See Driver.cc for definitions.
	//

	// Main driver, invoked by constructor.
	void Compile(bool report_uncompilable);

	// The following methods all create objects that track the
	// initializations of a given type of value.  In each, "tag"
	// is the name used to identify the initializer global
	// associated with the given type of value, and "type" is
	// its C++ representation.  Often "tag" is concatenated with
	// "type" to designate a specific C++ type.  For example,
	// "tag" might be "Double" and "type" might be "ValPtr";
	// the resulting global's type is "DoubleValPtr".

	// Creates an object for tracking values associated with Zeek
	// constants.  "c_type" is the C++ type used in the initializer
	// for each object; or, if empty, it specifies that we represent
	// the value using an index into a separate vector that holds
	// the constant.
	std::shared_ptr<CPP_InitsInfo> CreateConstInitInfo(const char* tag, const char* type,
	                                                   const char* c_type);

	// Creates an object for tracking compound initializers, which
	// are whose initialization uses indexes into other vectors.
	std::shared_ptr<CPP_InitsInfo> CreateCompoundInitInfo(const char* tag, const char* type);

	// Creates an object for tracking initializers that have custom
	// C++ objects to hold their initialization information.
	std::shared_ptr<CPP_InitsInfo> CreateCustomInitInfo(const char* tag, const char* type);

	// Generates the declaration associated with a set of initializations
	// and tracks the object to facilitate looping over all so
	// initializations.  As a convenience, returns the object.
	std::shared_ptr<CPP_InitsInfo> RegisterInitInfo(const char* tag, const char* type,
	                                                std::shared_ptr<CPP_InitsInfo> gi);

	// Generate the beginning of the compiled code: run-time functions,
	// namespace, auxiliary globals.
	void GenProlog();

	// Given the name of a function body that's been compiled, generate
	// code to register it at run-time, and track its associated hash
	// so subsequent compilations can reuse it.
	void RegisterCompiledBody(const std::string& f);

	// After compilation, generate the final code.  Most of this is
	// in support of run-time initialization of various dynamic values.
	void GenEpilog();

	// Generate the main method of the CPPDynStmt class, doing dynamic
	// dispatch for function invocation.
	void GenCPPDynStmt();

	// Generate a function to load BiFs.
	void GenLoadBiFs();

	// Generate the main initialization function, which finalizes
	// the run-time environment.
	void GenFinishInit();

	// Generate the function that registers compiled script bodies.
	void GenRegisterBodies();

	// True if the given function (plus body and profile) is one
	// that should be compiled.  If non-nil, sets reason to the
	// the reason why, if there's a fundamental problem.  If however
	// the function should be skipped for other reasons, then sets
	// it to nil.
	bool IsCompilable(const FuncInfo& func, const char** reason = nullptr);

	// The set of functions/bodies we're compiling.
	std::vector<FuncInfo>& funcs;

	// The global profile of all of the functions.
	ProfileFuncs& pfs;

	// Script functions that we are able to compile.  We compute
	// these ahead of time so that when compiling script function A
	// which makes a call to script function B, we know whether
	// B will indeed be compiled, or if it'll be interpreted due to
	// it including some functionality we don't currently support
	// for compilation.
	//
	// Indexed by the C++ name of the function.
	std::unordered_set<std::string> compilable_funcs;

	// Tracks which functions/hooks/events have at least one non-compilable
	// body.  Indexed by the Zeek name of function.
	std::unordered_set<std::string> not_fully_compilable;

	// Maps functions (not hooks or events) to upstream compiled names.
	std::unordered_map<std::string, std::string> hashed_funcs;

	// Tracks all of the module names used in activate_bodies__CPP()
	// calls, to ensure all of the global names of compiled-to-standalone
	// functions are available to subsequent scripts.
	std::unordered_set<std::string> module_names;

	// If non-zero, provides a tag used for auxiliary/additional
	// compilation units.
	int addl_tag = 0;

	// If true, the generated code should run "standalone".
	bool standalone = false;

	// Hash over the functions in this compilation.  This is only
	// needed for "seatbelts", to ensure that we can produce a
	// unique hash relating to this compilation (*and* its
	// compilation time, which is why these are "seatbelts" and
	// likely not important to make distinct).
	p_hash_type total_hash = 0;

	// Working directory in which we're compiling.  Used to quasi-locate
	// error messages when doing test-suite "add-C++" crunches.
	std::string working_dir;

	//
	// End of methods related to script/C++ variables.

	// Start of methods related to script variables and their C++
	// counterparts.
	// See Vars.cc for definitions.
	//

	// Generate declarations associated with the given global, and, if
	// it's used as a variable (not just as a function being called),
	// track it as such.
	void CreateGlobal(const ID* g);

	// Register the given identifier as a BiF.  If is_var is true
	// then the BiF is also used in a non-call context.
	void AddBiF(const ID* b, bool is_var);

	// Register the given global name.  "suffix" distinguishs particular
	// types of globals, such as the names of bifs, global (non-function)
	// variables, or compiled Zeek functions.
	bool AddGlobal(const std::string& g, const char* suffix);

	// Tracks that the body we're currently compiling refers to the
	// given event.
	void RegisterEvent(std::string ev_name);

	// The following match various forms of identifiers to the
	// name used for their C++ equivalent.
	const char* IDName(const IDPtr& id) { return IDName(id.get()); }
	const char* IDName(const ID* id) { return IDNameStr(id).c_str(); }
	const std::string& IDNameStr(const ID* id);

	// Returns a canonicalized version of a variant of a global made
	// distinct by the given suffix.
	std::string GlobalName(const std::string& g, const char* suffix)
		{
		return Canonicalize(g.c_str()) + "_" + suffix;
		}

	// Returns a canonicalized form of a local identifier's name,
	// expanding its module prefix if needed.
	std::string LocalName(const ID* l) const;
	std::string LocalName(const IDPtr& l) const { return LocalName(l.get()); }

	// Returns a canonicalized name, with various non-alphanumeric
	// characters stripped or transformed, and guananteed not to
	// conflict with C++ keywords.
	std::string Canonicalize(const char* name) const;

	// Returns the name of the global corresponding to an expression
	// (which must be a EXPR_NAME).
	std::string GlobalName(const ExprPtr& e) { return globals[e->AsNameExpr()->Id()->Name()]; }

	// Maps global names (not identifiers) to the names we use for them.
	std::unordered_map<std::string, std::string> globals;

	// Similar for locals, for the function currently being compiled.
	std::unordered_map<const ID*, std::string> locals;

	// Retrieves the initialization information associated with the
	// given global.
	std::unordered_map<const ID*, std::shared_ptr<CPP_InitInfo>> global_gis;

	// Maps event names to the names we use for them.
	std::unordered_map<std::string, std::string> events;

	// Globals that correspond to variables, not functions.
	IDSet global_vars;

	//
	// End of methods related to script/C++ variables.

	// Start of methods related to declaring compiled script functions,
	// including related classes.
	// See DeclFunc.cc for definitions.
	//

	// Generates declarations (class, forward reference to C++ function)
	// for the given script function.
	void DeclareFunc(const FuncInfo& func);

	// Similar, but for lambdas.
	void DeclareLambda(const LambdaExpr* l, const ProfileFunc* pf);

	// Generates code to declare the compiled version of a script
	// function.  "ft" gives the functions type, "pf" its profile,
	// "fname" its C++ name, "body" its AST, "l" if non-nil its
	// corresponding lambda expression, and "flavor" whether it's
	// a hook/event/function.
	//
	// We use two basic approaches.  Most functions are represented
	// by a "CPPDynStmt" object that's parameterized by a void* pointer
	// to the underlying C++ function and an index used to dynamically
	// cast the pointer to having the correct type for then calling it.
	// Lambdas, however (including "implicit" lambdas used to associate
	// complex expressions with &attributes), each have a unique
	// subclass derived from CPPStmt that calls the underlying C++
	// function without requiring a cast, and that holds the values
	// of the lambda's captures.
	//
	// It would be cleanest to use the latter approach for all functions,
	// but the hundreds/thousands of additional classes required for
	// doing so significantly slows down C++ compilation, so we instead
	// opt for the uglier dynamic casting approach, which only requires
	// one additional class.
	void CreateFunction(const FuncTypePtr& ft, const ProfileFunc* pf, const std::string& fname,
	                    const StmtPtr& body, int priority, const LambdaExpr* l,
	                    FunctionFlavor flavor);

	// Used for the case of creating a custom subclass of CPPStmt.
	void DeclareSubclass(const FuncTypePtr& ft, const ProfileFunc* pf, const std::string& fname,
	                     const std::string& args, const IDPList* lambda_ids);

	// Used for the case of employing an instance of a CPPDynStmt object.
	void DeclareDynCPPStmt();

	// Generates the declarations (and in-line definitions) associated
	// with compiling a lambda.
	void BuildLambda(const FuncTypePtr& ft, const ProfileFunc* pf, const std::string& fname,
	                 const StmtPtr& body, const LambdaExpr* l, const IDPList* lambda_ids);

	// For a call to the C++ version of a function of type "ft" and
	// with lambda captures lambda_ids (nil if not applicable), generates
	// code that binds the Interpreter arguments (i.e., Frame offsets)
	// to C++ function arguments, as well as passing in the captures.
	std::string BindArgs(const FuncTypePtr& ft, const IDPList* lambda_ids);

	// Generates the declaration for the parameters for a function with
	// the given type, lambda captures (if non-nil), and profile.
	std::string ParamDecl(const FuncTypePtr& ft, const IDPList* lambda_ids, const ProfileFunc* pf);

	// Returns in p_types the types associated with the parameters for a function
	// of the given type, set of lambda captures (if any), and profile.
	void GatherParamTypes(std::vector<std::string>& p_types, const FuncTypePtr& ft,
	                      const IDPList* lambda_ids, const ProfileFunc* pf);

	// Same, but instead returns the parameter's names.
	void GatherParamNames(std::vector<std::string>& p_names, const FuncTypePtr& ft,
	                      const IDPList* lambda_ids, const ProfileFunc* pf);

	// Inspects the given profile to find the i'th parameter (starting
	// at 0).  Returns nil if the profile indicates that that parameter
	// is not used by the function.
	const ID* FindParam(int i, const ProfileFunc* pf);

	// Information associated with a CPPDynStmt dynamic dispatch.
	struct DispatchInfo
		{
		std::string cast; // C++ cast to use for function pointer
		std::string args; // arguments to pass to the function
		bool is_hook; // whether the function is a hook
		TypePtr yield; // what type the function returns, if any
		};

	// An array of cast/invocation pairs used to generate the CPPDynStmt
	// Exec method.
	std::vector<DispatchInfo> func_casting_glue;

	// Maps casting strings to indices into func_casting_glue.  The index
	// is what's used to dynamically switch to the right dispatch.
	std::unordered_map<std::string, int> casting_index;

	// Maps functions (using their C++ name) to their casting strings.
	std::unordered_map<std::string, std::string> func_index;

	// Names for lambda capture ID's.  These require a separate space
	// that incorporates the lambda's name, to deal with nested lambda's
	// that refer to the identifiers with the same name.
	std::unordered_map<const ID*, std::string> lambda_names;

	// The function's parameters.  Tracked so we don't re-declare them.
	IDSet params;

	// Whether we're compiling a hook.
	bool in_hook = false;

	//
	// End of methods related to declaring compiled script functions.

	// Start of methods related to generating the bodies of compiled
	// script functions.  Note that some of this sort of functionality is
	// instead in CPPDeclFunc.cc, due to the presence of inlined methods.
	// See GenFunc.cc for definitions.
	//

	// Driver functions for compiling the body of the given function
	// or lambda.
	void CompileFunc(const FuncInfo& func);
	void CompileLambda(const LambdaExpr* l, const ProfileFunc* pf);

	// Generates the body of the Invoke() method (which supplies the
	// "glue" for calling the C++-generated code, for CPPStmt subclasses).
	void GenInvokeBody(const std::string& fname, const TypePtr& t, const std::string& args)
		{
		GenInvokeBody(fname + "(" + args + ")", t);
		}
	void GenInvokeBody(const std::string& call, const TypePtr& t);

	// Generates the code for the body of a script function with
	// the given type, profile, C++ name, AST, lambda captures
	// (if non-nil), and hook/event/function "flavor".
	void DefineBody(const FuncTypePtr& ft, const ProfileFunc* pf, const std::string& fname,
	                const StmtPtr& body, const IDPList* lambda_ids, FunctionFlavor flavor);

	// Declare parameters that originate from a type signature of
	// "any" but were concretized in this declaration.
	void TranslateAnyParams(const FuncTypePtr& ft, const ProfileFunc* pf);

	// Generates code to dynamically initialize any events referred to
	// in the function.
	void InitializeEvents(const ProfileFunc* pf);

	// Declare local variables (which are non-globals that aren't
	// parameters or lambda captures).
	void DeclareLocals(const ProfileFunc* func, const IDPList* lambda_ids);

	// Returns the C++ name to use for a given function body.
	std::string BodyName(const FuncInfo& func);

	// Generate the arguments to be used when calling a C++-generated
	// function.
	std::string GenArgs(const RecordTypePtr& params, const Expr* e);

	// Functions that we've declared/compiled.  Indexed by full C++ name.
	std::unordered_set<std::string> compiled_funcs;

	// "Simple" functions that we've compiled, i.e., those that have
	// a single body and thus can be called directly.  Indexed by
	// function name, and maps to the C++ name.
	std::unordered_map<std::string, std::string> compiled_simple_funcs;

	// Maps function bodies to the names we use for them.
	std::unordered_map<const Stmt*, std::string> body_names;

	// Maps function names to hashes of bodies.
	std::unordered_map<std::string, p_hash_type> body_hashes;

	// Maps function names to priorities, for hooks & event handlers.
	std::unordered_map<std::string, int> body_priorities;

	// Maps function names to events relevant to them.
	std::unordered_map<std::string, std::vector<std::string>> body_events;

	// Return type of the function we're currently compiling.
	TypePtr ret_type = nullptr;

	// Internal name of the function we're currently compiling.
	std::string body_name;

	//
	// End of methods related to generating compiled script bodies.

	// Methods related to generating code for representing script constants
	// as run-time values.  There's only one nontrivial one of these,
	// RegisterConstant() (declared above, as it's public).  All the other
	// work is done by secondary objects - see InitsInfo.{h,cc} for those.

	// Returns the object used to track indices (vectors of integers
	// that are used to index various other vectors, including other
	// indices).  Only used by CPP_InitsInfo objects, but stored
	// in the CPPCompile object to make it available across different
	// CPP_InitsInfo objects.

	friend class CPP_InitsInfo;
	IndicesManager& IndMgr() { return indices_mgr; }

	// Maps (non-native) constants to associated C++ globals.
	std::unordered_map<const ConstExpr*, std::string> const_exprs;

	// Maps the values of (non-native) constants to associated initializer
	// information.
	std::unordered_map<const Val*, std::shared_ptr<CPP_InitInfo>> const_vals;

	// Same, but for the offset into the vector that tracks all constants
	// collectively (to support initialization of compound constants).
	std::unordered_map<const Val*, int> const_offsets;

	// The same as the above pair, but indexed by the string representation
	// rather than the Val*.  The reason for having both is to enable
	// reusing common constants even though their Val*'s differ.
	std::unordered_map<std::string, std::shared_ptr<CPP_InitInfo>> constants;
	std::unordered_map<std::string, int> constants_offsets;

	// Used for memory management associated with const_vals's index.
	std::vector<ValPtr> cv_indices;

	// For different types of constants (as indicated by TypeTag),
	// provides the associated object that manages the initializers
	// for those constants.
	std::unordered_map<TypeTag, std::shared_ptr<CPP_InitsInfo>> const_info;

	// Tracks entries for constructing the vector of all constants
	// (regardless of type).  Each entry provides a TypeTag, used
	// to identify the type-specific vector for a given constant,
	// and the offset into that vector.
	std::vector<std::pair<TypeTag, int>> consts;

	// The following objects track initialization information for
	// different types of initializers: Zeek types, individual
	// attributes, sets of attributes, expressions that call script
	// functions (for attribute expressions), registering lambda
	// bodies, and registering Zeek globals.
	std::shared_ptr<CPP_InitsInfo> type_info;
	std::shared_ptr<CPP_InitsInfo> attr_info;
	std::shared_ptr<CPP_InitsInfo> attrs_info;
	std::shared_ptr<CPP_InitsInfo> call_exprs_info;
	std::shared_ptr<CPP_InitsInfo> lambda_reg_info;
	std::shared_ptr<CPP_InitsInfo> global_id_info;

	// Tracks all of the above objects (as well as each entry in
	// const_info), to facilitate easy iterating over them.
	std::set<std::shared_ptr<CPP_InitsInfo>> all_global_info;

	// Tracks the attribute expressions for which we need to generate
	// function calls to evaluate them.
	std::unordered_map<std::string, std::shared_ptr<CallExprInitInfo>> init_infos;

	// See IndMgr() above for the role of this variable.
	IndicesManager indices_mgr;

	// Maps strings to associated offsets.
	std::unordered_map<std::string, int> tracked_strings;

	// Tracks strings we've registered in order (corresponding to
	// their offsets).
	std::vector<std::string> ordered_tracked_strings;

	// The same as the previous two, but for profile hashes.
	std::vector<p_hash_type> ordered_tracked_hashes;
	std::unordered_map<p_hash_type, int> tracked_hashes;

	//
	// End of methods related to generating code for script constants.

	// Start of methods related to generating code for AST Stmt's.
	// For the most part, code generation is straightforward as
	// it matches the Exec/DoExec methods of the corresponding
	// Stmt subclasses.
	// See Stmts.cc for definitions.
	//

	void GenStmt(const StmtPtr& s) { GenStmt(s.get()); }
	void GenStmt(const Stmt* s);
	void GenInitStmt(const InitStmt* init);
	void GenIfStmt(const IfStmt* i);
	void GenWhileStmt(const WhileStmt* w);
	void GenReturnStmt(const ReturnStmt* r);
	void GenAddStmt(const ExprStmt* es);
	void GenDeleteStmt(const ExprStmt* es);
	void GenEventStmt(const EventStmt* ev);

	void GenSwitchStmt(const SwitchStmt* sw);
	void GenTypeSwitchStmt(const Expr* e, const case_list* cases);
	void GenTypeSwitchCase(const ID* id, int case_offset, bool is_multi);
	void GenValueSwitchStmt(const Expr* e, const case_list* cases);

	void GenWhenStmt(const WhenStmt* w);
	void GenForStmt(const ForStmt* f);
	void GenForOverTable(const ExprPtr& tbl, const IDPtr& value_var, const IDPList* loop_vars);
	void GenForOverVector(const ExprPtr& tbl, const IDPtr& value_var, const IDPList* loop_vars);
	void GenForOverString(const ExprPtr& str, const IDPList* loop_vars);

	// Nested level of loops/switches for which "break"'s should be
	// C++ breaks rather than a "hook" break.
	int break_level = 0;

	//
	// End of methods related to generating code for AST Stmt's.

	// Start of methods related to generating code for AST Expr's.
	// See Exprs.cc for definitions.
	//

	// These methods are all oriented around returning strings
	// of C++ code; they do not directly emit the code, since often
	// the caller will be embedding the result in some surrounding
	// context.  No effort is made to reduce string copying; this
	// isn't worth the hassle, as it takes just a few seconds for
	// the compiler to generate 100K+ LOC that clang will then need
	// 10s of seconds to compile, so speeding up the compiler has
	// little practical advantage.

	// The following enum's represent whether, for expressions yielding
	// native values, the end goal is to have the value in (1) native
	// form, (2) instead in ValPtr form, or (3) whichever is more
	// convenient to generate (sometimes used when the caller knows
	// that the value is non-native).
	enum GenType
		{
		GEN_NATIVE,
		GEN_VAL_PTR,
		GEN_DONT_CARE,
		};

	// Generate an expression for which we want the result embedded
	// in {} initializers (generally to be used in calling a function
	// where we want those values to be translated to a vector<ValPtr>).
	std::string GenExprs(const Expr* e);

	// Generate the value(s) associated with a ListExpr.  If true,
	// the "nested" parameter indicates that this list is embedded
	// within an outer list, in which case it's expanded to include
	// {}'s.  It's false if the ListExpr is at the top level, such
	// as when expanding the arguments in a CallExpr.
	std::string GenListExpr(const Expr* e, GenType gt, bool nested);

	// Per-Expr-subclass code generation.  The resulting code generally
	// reflects the corresponding Eval() or Fold() methods.
	std::string GenExpr(const ExprPtr& e, GenType gt, bool top_level = false)
		{
		return GenExpr(e.get(), gt, top_level);
		}
	std::string GenExpr(const Expr* e, GenType gt, bool top_level = false);

	std::string GenNameExpr(const NameExpr* ne, GenType gt);
	std::string GenConstExpr(const ConstExpr* c, GenType gt);
	std::string GenIncrExpr(const Expr* e, GenType gt, bool is_incr, bool top_level);
	std::string GenCondExpr(const Expr* e, GenType gt);
	std::string GenCallExpr(const CallExpr* c, GenType gt);
	std::string GenInExpr(const Expr* e, GenType gt);
	std::string GenFieldExpr(const FieldExpr* fe, GenType gt);
	std::string GenHasFieldExpr(const HasFieldExpr* hfe, GenType gt);
	std::string GenIndexExpr(const Expr* e, GenType gt);
	std::string GenAssignExpr(const Expr* e, GenType gt, bool top_level);
	std::string GenAddToExpr(const Expr* e, GenType gt, bool top_level);
	std::string GenRemoveFromExpr(const Expr* e, GenType gt, bool top_level);
	std::string GenSizeExpr(const Expr* e, GenType gt);
	std::string GenScheduleExpr(const Expr* e);
	std::string GenLambdaExpr(const Expr* e);
	std::string GenIsExpr(const Expr* e, GenType gt);

	std::string GenArithCoerceExpr(const Expr* e, GenType gt);
	std::string GenRecordCoerceExpr(const Expr* e);
	std::string GenTableCoerceExpr(const Expr* e);
	std::string GenVectorCoerceExpr(const Expr* e);

	std::string GenRecordConstructorExpr(const Expr* e);
	std::string GenSetConstructorExpr(const Expr* e);
	std::string GenTableConstructorExpr(const Expr* e);
	std::string GenVectorConstructorExpr(const Expr* e);

	// Generate code for constants that can be expressed directly
	// as C++ constants.
	std::string GenVal(const ValPtr& v);

	// Helper functions for particular Expr subclasses / flavors.
	std::string GenUnary(const Expr* e, GenType gt, const char* op, const char* vec_op = nullptr);
	std::string GenBinary(const Expr* e, GenType gt, const char* op, const char* vec_op = nullptr);
	std::string GenBinarySet(const Expr* e, GenType gt, const char* op);
	std::string GenBinaryString(const Expr* e, GenType gt, const char* op);
	std::string GenBinaryPattern(const Expr* e, GenType gt, const char* op);
	std::string GenBinaryAddr(const Expr* e, GenType gt, const char* op);
	std::string GenBinarySubNet(const Expr* e, GenType gt, const char* op);
	std::string GenEQ(const Expr* e, GenType gt, const char* op, const char* vec_op);

	std::string GenAssign(const ExprPtr& lhs, const ExprPtr& rhs, const std::string& rhs_native,
	                      const std::string& rhs_val_ptr, GenType gt, bool top_level);
	std::string GenDirectAssign(const ExprPtr& lhs, const std::string& rhs_native,
	                            const std::string& rhs_val_ptr, GenType gt, bool top_level);
	std::string GenIndexAssign(const ExprPtr& lhs, const ExprPtr& rhs,
	                           const std::string& rhs_val_ptr, GenType gt, bool top_level);
	std::string GenFieldAssign(const ExprPtr& lhs, const ExprPtr& rhs,
	                           const std::string& rhs_val_ptr, GenType gt, bool top_level);
	std::string GenListAssign(const ExprPtr& lhs, const ExprPtr& rhs);

	// Support for element-by-element vector operations.
	std::string GenVectorOp(const Expr* e, std::string op, const char* vec_op);
	std::string GenVectorOp(const Expr* e, std::string op1, std::string op2, const char* vec_op);

	// If "all_deep" is true, it means make all of the captures
	// deep copies, not just the ones that were explicitly marked
	// as deep copies.  That functionality is used to supporting
	// Clone() methods; it's not needed when creating a new lambda
	// instance.
	std::string GenLambdaClone(const LambdaExpr* l, bool all_deep);

	// Returns an initializer list for a vector of integers.
	std::string GenIntVector(const std::vector<int>& vec);

	// The following are used to generate accesses to elements of
	// extensible types.  They first check whether the type has
	// been extended (for records, beyond the field of interest);
	// if not, then the access is done directly.  If the access
	// is however to an extended element, then they indirect the
	// access through a map that is generated dynamically when
	// the compiled code.  Doing so allows the compiled code to
	// work in contexts where other extensions occur that would
	// otherwise conflict with hardwired offsets/values.
	std::string GenField(const ExprPtr& rec, int field);
	std::string GenEnum(const TypePtr& et, const ValPtr& ev);

	// For record that are extended via redef's, maps fields
	// beyond the original definition to locations in the
	// global (in the compiled code) "field_mapping" array.
	//
	// So for each such record, there's a second map of
	// field-in-the-record to offset-in-field_mapping.
	std::unordered_map<const RecordType*, std::unordered_map<int, int>> record_field_mappings;

	// Total number of such mappings (i.e., entries in the inner maps,
	// not the outer map).
	int num_rf_mappings = 0;

	// For each entry in "field_mapping", the record (as a global
	// offset) and TypeDecl associated with the mapping.
	std::vector<std::pair<int, const TypeDecl*>> field_decls;

	// For enums that are extended via redef's, maps each distinct
	// value (that the compiled scripts refer to) to locations in the
	// global (in the compiled code) "enum_mapping" array.
	//
	// So for each such enum, there's a second map of
	// value-during-compilation to offset-in-enum_mapping.
	std::unordered_map<const EnumType*, std::unordered_map<int, int>> enum_val_mappings;

	// Total number of such mappings (i.e., entries in the inner maps,
	// not the outer map).
	int num_ev_mappings = 0;

	// For each entry in "enum_mapping", the EnumType (as a global
	// offset) and name associated with the mapping.
	std::vector<std::pair<int, std::string>> enum_names;

	//
	// End of methods related to generating code for AST Expr's.

	// Start of methods related to managing script types.
	// See Types.cc for definitions.
	//

	// "Native" types are those Zeek scripting types that we support
	// using low-level C++ types (like "zeek_uint_t" for "count").
	// Types that we instead support using some form of ValPtr
	// representation are "non-native".
	bool IsNativeType(const TypePtr& t) const;

	// Given an expression corresponding to a native type (and with
	// the given script type 't'), converts it to the given GenType.
	std::string NativeToGT(const std::string& expr, const TypePtr& t, GenType gt);

	// Given an expression with a C++ type of generic "ValPtr", of the
	// given script type 't', converts it as needed to the given GenType.
	std::string GenericValPtrToGT(const std::string& expr, const TypePtr& t, GenType gt);

	// Returns the name of a C++ variable that will hold a TypePtr
	// of the appropriate flavor.  't' does not need to be a type
	// representative.
	std::string GenTypeName(const Type* t);
	std::string GenTypeName(const TypePtr& t) { return GenTypeName(t.get()); }

	// Returns the "representative" for a given type, used to ensure
	// that we re-use the C++ variable corresponding to a type and
	// don't instantiate redundant instances.
	const Type* TypeRep(const Type* t) { return pfs.TypeRep(t); }
	const Type* TypeRep(const TypePtr& t) { return TypeRep(t.get()); }

	// Low-level C++ representations for types, of various flavors.
	static const char* TypeTagName(TypeTag tag);
	const char* TypeName(const TypePtr& t);
	const char* FullTypeName(const TypePtr& t);
	const char* TypeType(const TypePtr& t);

	// Access to a type's underlying values.
	const char* NativeAccessor(const TypePtr& t);

	// The name for a type that should be used in declaring
	// an IntrusivePtr to such a type.
	const char* IntrusiveVal(const TypePtr& t);

	// Maps types to indices in the global "types__CPP" array.
	CPPTracker<Type> types = {"types", true};

	// Used to prevent analysis of mutually-referring types from
	// leading to infinite recursion.  Maps types to their global
	// initialization information (or, initially, to nullptr, if
	// they're in the process of being registered).
	std::unordered_map<const Type*, std::shared_ptr<CPP_InitInfo>> processed_types;

	//
	// End of methods related to managing script types.

	// Start of methods related to managing script type attributes.
	// Attributes arise mainly in the context of constructing types.
	// See Attrs.cc for definitions.
	//

	// Populates the 2nd and 3rd arguments with C++ representations
	// of the tags and (optional) values/expressions associated with
	// the set of attributes.
	void BuildAttrs(const AttributesPtr& attrs, std::string& attr_tags, std::string& attr_vals);

	// Returns a string representation of the name associated with
	// different attribute tags (e.g., "ATTR_DEFAULT").
	static const char* AttrName(AttrTag t);

	// Similar for attributes, so we can reconstruct record types.
	CPPTracker<Attributes> attributes = {"attrs", false};

	// Maps Attributes and Attr's to their global initialization
	// information.
	std::unordered_map<const Attributes*, std::shared_ptr<CPP_InitInfo>> processed_attrs;
	std::unordered_map<const Attr*, std::shared_ptr<CPP_InitInfo>> processed_attr;

	//
	// End of methods related to managing script type attributes.

	// Start of methods related to run-time initialization.
	// See Inits.cc for definitions.
	//

	// Generates code for dynamically generating an expression
	// associated with an attribute, via a function call.
	void GenInitExpr(std::shared_ptr<CallExprInitInfo> ce_init);

	// Returns the name of a function used to evaluate an
	// initialization expression.
	std::string InitExprName(const ExprPtr& e);

	// Convenience functions for return the offset or initialization cohort
	// associated with an initialization.
	int GI_Offset(const std::shared_ptr<CPP_InitInfo>& gi) const { return gi ? gi->Offset() : -1; }
	int GI_Cohort(const std::shared_ptr<CPP_InitInfo>& gi) const
		{
		return gi ? gi->InitCohort() : 0;
		}

	// Generate code to initialize the mappings for record field
	// offsets for field accesses into regions of records that
	// can be extensible (and thus can vary at run-time to the
	// offsets encountered during compilation).
	void InitializeFieldMappings();

	// Same, but for enum types.
	void InitializeEnumMappings();

	// Generate code to initialize BiFs.
	void InitializeBiFs();

	// Generate code to initialize strings that we track.
	void InitializeStrings();

	// Generate code to initialize hashes that we track.
	void InitializeHashes();

	// Generate code to initialize indirect references to constants.
	void InitializeConsts();

	// Generate code to initialize globals (using dynamic statements
	// rather than constants).
	void InitializeGlobals();

	// Generate the initialization hook for this set of compiled code.
	void GenInitHook();

	// Generates code to activate standalone code.
	void GenStandaloneActivation();

	// Generates code to register the initialization for standalone
	// use, and prints to stdout a Zeek script that can load all of
	// what we compiled.
	void GenLoad();

	// A list of BiFs to look up during initialization.  First
	// string is the name of the C++ global holding the BiF, the
	// second is its name as known to Zeek.
	std::unordered_map<std::string, std::string> BiFs;

	// Expressions for which we need to generate initialization-time
	// code.  Currently, these are only expressions appearing in
	// attributes.
	CPPTracker<Expr> init_exprs = {"gen_init_expr", false};

	//
	// End of methods related to run-time initialization.

	// Start of methods related to low-level code generation.
	// See Emit.cc for definitions.
	//

	// The following all need to be able to emit code.
	friend class CPP_BasicConstInitsInfo;
	friend class CPP_CompoundInitsInfo;
	friend class IndicesManager;

	// Used to create (indented) C++ {...} code blocks.  "needs_semi"
	// controls whether to terminate the block with a ';' (such as
	// for class definitions.
	void StartBlock();
	void EndBlock(bool needs_semi = false);

	void IndentUp() { ++block_level; }
	void IndentDown() { --block_level; }

	// Various ways of generating code.  The multi-argument methods
	// assume that the first argument is a printf-style format
	// (but one that can only have %s specifiers).
	void Emit(const std::string& str) const
		{
		Indent();
		fprintf(write_file, "%s", str.c_str());
		NL();
		}

	void Emit(const std::string& fmt, const std::string& arg, bool do_NL = true) const
		{
		Indent();
		fprintf(write_file, fmt.c_str(), arg.c_str());
		if ( do_NL )
			NL();
		}

	void Emit(const std::string& fmt, const std::string& arg1, const std::string& arg2) const
		{
		Indent();
		fprintf(write_file, fmt.c_str(), arg1.c_str(), arg2.c_str());
		NL();
		}

	void Emit(const std::string& fmt, const std::string& arg1, const std::string& arg2,
	          const std::string& arg3) const
		{
		Indent();
		fprintf(write_file, fmt.c_str(), arg1.c_str(), arg2.c_str(), arg3.c_str());
		NL();
		}

	void Emit(const std::string& fmt, const std::string& arg1, const std::string& arg2,
	          const std::string& arg3, const std::string& arg4) const
		{
		Indent();
		fprintf(write_file, fmt.c_str(), arg1.c_str(), arg2.c_str(), arg3.c_str(), arg4.c_str());
		NL();
		}

	void Emit(const std::string& fmt, const std::string& arg1, const std::string& arg2,
	          const std::string& arg3, const std::string& arg4, const std::string& arg5) const
		{
		Indent();
		fprintf(write_file, fmt.c_str(), arg1.c_str(), arg2.c_str(), arg3.c_str(), arg4.c_str(),
		        arg5.c_str());
		NL();
		}

	void Emit(const std::string& fmt, const std::string& arg1, const std::string& arg2,
	          const std::string& arg3, const std::string& arg4, const std::string& arg5,
	          const std::string& arg6) const
		{
		Indent();
		fprintf(write_file, fmt.c_str(), arg1.c_str(), arg2.c_str(), arg3.c_str(), arg4.c_str(),
		        arg5.c_str(), arg6.c_str());
		NL();
		}

	void NL() const { fputc('\n', write_file); }

	// Indents to the current indentation level.
	void Indent() const;

	// File to which we're generating code.
	FILE* write_file;

	// Indentation level.
	int block_level = 0;

	//
	// End of methods related to run-time initialization.
	};

	} // zeek::detail
