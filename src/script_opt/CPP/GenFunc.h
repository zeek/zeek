// See the file "COPYING" in the main distribution directory for copyright.

// Methods for generating function/lambda definitions. The counterpart
// to DeclFunc.cc.
//
// This file is included by Compile.h to insert into the CPPCompiler class.

// Driver functions for compiling the body of the given function or lambda.
void CompileFunc(const FuncInfo& func);
void CompileLambda(const LambdaExpr* l, const ProfileFunc* pf);

// Generates the body of the Invoke() method (which supplies the "glue"
// for calling the C++-generated code, for CPPStmt subclasses).
void GenInvokeBody(const std::string& fname, const TypePtr& t, const std::string& args) {
    GenInvokeBody(fname + "(" + args + ")", t);
}
void GenInvokeBody(const std::string& call, const TypePtr& t);

// Generates the code for the body of a script function with the given
// type, profile, C++ name, AST, lambda captures (if non-nil), and
// hook/event/function "flavor".
void DefineBody(const FuncTypePtr& ft, const ProfileFunc* pf, const std::string& fname, const StmtPtr& body,
                const IDPList* lambda_ids, FunctionFlavor flavor);

// Declare parameters that originate from a type signature of "any" but were
// concretized in this declaration.
void TranslateAnyParams(const FuncTypePtr& ft, const ProfileFunc* pf);

// Generates code to dynamically initialize any events referred to in the
// function.
void InitializeEvents(const ProfileFunc* pf);

// Declare local variables (which are non-globals that aren't parameters or
// lambda captures).
void DeclareLocals(const ProfileFunc* func, const IDPList* lambda_ids);

// Returns the C++ name to use for a given function body.
std::string BodyName(const FuncInfo& func);

// Generate the arguments to be used when calling a C++-generated function.
std::string GenArgs(const RecordTypePtr& params, const Expr* e);

// Functions that we've declared/compiled.  Indexed by full C++ name.
std::unordered_set<std::string> compiled_funcs;

// "Simple" functions that we've compiled, i.e., those that have a single
// body and thus can be called directly.  Indexed by function name, and
// maps to the C++ name.
std::unordered_map<std::string, std::string> compiled_simple_funcs;

// Maps function bodies to the names we use for them.
std::unordered_map<const Stmt*, std::string> body_names;

struct BodyInfo {
    p_hash_type hash;
    int priority;
    const Location* loc; // for better-than-nothing error reporting
};

// Maps function names to their body info.
std::unordered_map<std::string, BodyInfo> body_info;

// Maps function names to events relevant to them.
std::unordered_map<std::string, std::vector<std::string>> body_events;

// Full type of the function we're currently compiling.
FuncTypePtr func_type;

// Return type of the function we're currently compiling.
TypePtr ret_type;

// Internal name of the function we're currently compiling.
std::string body_name;
