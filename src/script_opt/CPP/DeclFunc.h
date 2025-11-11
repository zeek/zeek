// See the file "COPYING" in the main distribution directory for copyright.

// Methods for generating declarations of functions and lambdas.
// The counterpart to GenFunc.cc.
//
// This file is included by Compile.h to insert into the CPPCompiler class.

// Generates declarations (class, forward reference to C++ function) for the
// given script function.
void DeclareFunc(const FuncInfo& func);

// Similar, but for lambdas.
void DeclareLambda(const LambdaExpr* l, const ProfileFunc* pf);

// Generates code to declare the compiled version of a script function.
// "ft" gives the functions type, "pf" its profile, "fname" its C++ name,
// "body" its AST, "l" if non-nil its corresponding lambda expression, and
// "flavor" whether it's a hook/event/function.
//
// We use two basic approaches.  Most functions are represented by a
// "CPPDynStmt" object that's parameterized by a void* pointer to the
// underlying C++ function and an index used to dynamically cast the pointer
// to having the correct type for then calling it.  Lambdas, however
// (including "implicit" lambdas used to associate complex expressions with
// &attributes), each have a unique subclass derived from CPPStmt that calls
// the underlying C++ function without requiring a cast, and that holds the
// values of the lambda's captures.
//
// It would be cleanest to use the latter approach for all functions, but
// the hundreds/thousands of additional classes required for doing so
// significantly slows down C++ compilation, so we instead opt for the uglier
// dynamic casting approach, which only requires one additional class.

void CreateFunction(const FuncTypePtr& ft, const ProfileFunc* pf, const std::string& fname, const StmtPtr& body,
                    int priority, const LambdaExpr* l, FunctionFlavor flavor,
                    const std::forward_list<EventGroupPtr>* e_g = nullptr);

// Used for the case of creating a custom subclass of CPPStmt.
void DeclareSubclass(const FuncTypePtr& ft, const ProfileFunc* pf, const std::string& fname, const std::string& args,
                     const IDPList* lambda_ids);

// Used for the case of employing an instance of a CPPDynStmt object.
void DeclareDynCPPStmt();

// Generates the declarations (and in-line definitions) associated with
// compiling a lambda.
void BuildLambda(const FuncTypePtr& ft, const ProfileFunc* pf, const std::string& fname, const StmtPtr& body,
                 const LambdaExpr* l, const IDPList* lambda_ids);

// For a call to the C++ version of a function of type "ft" and with lambda
// captures lambda_ids (nil if not applicable), generates code that binds the
// Interpreter arguments (i.e., Frame offsets) to C++ function arguments, as
// well as passing in the captures.
std::string BindArgs(const FuncTypePtr& ft, const IDPList* lambda_ids);

// Generates the declaration for the parameters for a function with the given
// type, lambda captures (if non-nil), and profile.
std::string ParamDecl(const FuncTypePtr& ft, const IDPList* lambda_ids, const ProfileFunc* pf);

// Returns in p_types the types associated with the parameters for a function
// of the given type, set of lambda captures (if any), and profile.
void GatherParamTypes(std::vector<std::string>& p_types, const FuncTypePtr& ft, const IDPList* lambda_ids,
                      const ProfileFunc* pf);

// Same, but instead returns the parameter's names.
void GatherParamNames(std::vector<std::string>& p_names, const FuncTypePtr& ft, const IDPList* lambda_ids,
                      const ProfileFunc* pf);

// Inspects the given profile to find the i'th parameter (starting at 0).
// Returns nil if the profile indicates that the parameter is not used by the
// function.
IDPtr FindParam(int i, const ProfileFunc* pf);

// Information associated with a CPPDynStmt dynamic dispatch.
struct DispatchInfo {
    std::string cast; // C++ cast to use for function pointer
    std::string args; // arguments to pass to the function
    bool is_hook;     // whether the function is a hook
    TypePtr yield;    // what type the function returns, if any
};

// An array of cast/invocation pairs used to generate the CPPDynStmt Exec
// method.
std::vector<DispatchInfo> func_casting_glue;

// Maps casting strings to indices into func_casting_glue.  The index is
// what's used to dynamically switch to the right dispatch.
std::unordered_map<std::string, int> casting_index;

// Maps functions (using their C++ name) to their casting strings.
std::unordered_map<std::string, std::string> func_index;

// Functions that we've declared/compiled.  Indexed by full C++ name,
// yielding Zeek names.
std::unordered_map<std::string, std::string> compiled_func_to_zeek_func;

// Names for lambda capture ID's.  These require a separate space that
// incorporates the lambda's name, to deal with nested lambda's that refer
// to the identifiers with the same name.
std::unordered_map<IDPtr, std::string> lambda_names;

// The function's parameters.  Tracked so we don't re-declare them.
IDSet params;

// Whether we're compiling a hook.
bool in_hook = false;
