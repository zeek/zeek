// See the file "COPYING" in the main distribution directory for copyright.

// Methods for driving the overall "-O gen-C++" compilation process.
//
// This file is included by Compile.h to insert into the CPPCompiler class.

// Main driver, invoked by constructor.
void Compile(bool report_uncompilable);

// For a given function body, assess its compilability and track its elements.
// Returns true if the body was analyzed, false if it was skipped. If skipped
// then either generates a warning (if report_uncompilable is true) or
// updates filenames_reported_as_skipped. Updates rep_types with the type
// representatives seen in the function.
bool AnalyzeFuncBody(FuncInfo& fi, std::unordered_set<std::string>& filenames_reported_as_skipped,
                     std::unordered_set<const Type*>& rep_types, bool report_uncompilable);

// Generate the beginning of the compiled code: run-time functions,
// namespace, auxiliary globals.
void GenProlog();

// The following methods all create objects that track the initializations
// of a given type of value.  In each, "tag" is the name used to identify the
// initializer global associated with the given type of value, and "type" is
// its C++ representation.  Often "tag" is concatenated with "type" to designate
// a specific C++ type.  For example, "tag" might be "Double" and "type" might
// be "ValPtr"; the resulting global's type is "DoubleValPtr".

// Creates an object for tracking values associated with Zeek constants.
// "c_type" is the C++ type used in the initializer for each object; or, if
// empty, it specifies that we represent the value using an index into a
// separate vector that holds the constant.
std::shared_ptr<CPP_InitsInfo> CreateConstInitInfo(const char* tag, const char* type, const char* c_type);

// Creates an object for tracking compound initializers, which are whose
// initialization uses indexes into other vectors.
std::shared_ptr<CPP_InitsInfo> CreateCompoundInitInfo(const char* tag, const char* type);

// Creates an object for tracking initializers that have custom C++ objects
// to hold their initialization information.
std::shared_ptr<CPP_InitsInfo> CreateCustomInitInfo(const char* tag, const char* type);

// Generates the declaration associated with a set of initializations and
// tracks the object to facilitate looping over all so initializations.
// As a convenience, returns the object.
std::shared_ptr<CPP_InitsInfo> RegisterInitInfo(const char* tag, const char* type, std::shared_ptr<CPP_InitsInfo> gi);

// Given the name of a function body that's been compiled, generate code to
// register it at run-time, and track its associated hash so subsequent
// compilations can reuse it.
void RegisterCompiledBody(const std::string& f);

// After compilation, generate the final code.  Most of this is in support
// of run-time initialization of various dynamic values.
void GenEpilog();

// Generate the main method of the CPPDynStmt class, doing dynamic dispatch
// for function invocation.
void GenCPPDynStmt();

// Generate a function to load BiFs.
void GenLoadBiFs();

// Generate the main initialization function, which finalizes the run-time
// environment.
void GenFinishInit();

// Generate the function that registers compiled script bodies.
void GenRegisterBodies();

public:
// Whether we're generating "standalone" code.
bool TargetingStandalone() const { return standalone; }

private:
// True if the given function (plus body and profile) is one that should be
// compiled.  If non-nil, sets reason to the the reason why, if there's a
// fundamental problem.  If however the function should be skipped for other
// reasons, then sets it to nil.
bool IsCompilable(const FuncInfo& func, const char** reason = nullptr);

// The set of functions/bodies we're compiling.
std::vector<FuncInfo>& funcs;

// The global profile of all of the functions.
std::shared_ptr<ProfileFuncs> pfs;

// Script functions that we are able to compile.  We compute these ahead
// of time so that when compiling script function A which makes a call to
// script function B, we know whether B will indeed be compiled, or if it'll
// be interpreted due to it including some functionality we don't currently
// support for compilation.
//
// Indexed by the C++ name of the function.
std::unordered_set<std::string> compilable_funcs;

// Tracks which functions/hooks/events have at least one non-compilable body.
// Indexed by the Zeek name of function.
std::unordered_set<std::string> not_fully_compilable;

// Maps functions (not hooks or events) to upstream compiled names.
std::unordered_map<std::string, std::string> hashed_funcs;

// If true, the generated code should run "standalone".
bool standalone = false;

// If true, compilation skipped at least one function due to non-compilability.
bool skipped_uncompilable_func = false;

// Hash over the functions in this compilation.  This is only needed for
// "seatbelts", to ensure that we can produce a unique hash relating to this
// compilation (*and* its compilation time, which is why these are "seatbelts"
// and likely not important to make distinct).
p_hash_type total_hash = 0;
