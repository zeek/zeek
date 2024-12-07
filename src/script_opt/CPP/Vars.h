// See the file "COPYING" in the main distribution directory for copyright.

// Methods related to Zeek script variables and their C++ counterparts.
//
// This file is included by Compile.h to insert into the CPPCompiler class.

public:
// Tracks a global to generate the necessary initialization.
// Returns the associated initialization info.
std::shared_ptr<CPP_InitInfo> RegisterGlobal(const ID* g);

private:
// Generate declarations associated with the given global, and, if it's used
// as a variable (not just as a function being called), track it as such.
void CreateGlobal(const ID* g);

// Register the given identifier as a BiF.  If is_var is true then the BiF
// is also used in a non-call context.
void AddBiF(const ID* b, bool is_var);

// Register the given global name.  "suffix" distinguishes particular types
// of globals, such as the names of bifs, global (non-function) variables,
// or compiled Zeek functions.
bool AddGlobal(const std::string& g, const char* suffix);

// Tracks that the body we're currently compiling refers to the given event.
void RegisterEvent(std::string ev_name);

// The following match various forms of identifiers to the name used for
// their C++ equivalent.
const char* IDName(const IDPtr& id) { return IDName(id.get()); }
const char* IDName(const ID* id) { return IDNameStr(id).c_str(); }
const std::string& IDNameStr(const ID* id);

// Returns a canonicalized version of a variant of a global made distinct by
// the given suffix.
std::string GlobalName(const std::string& g, const char* suffix) { return Canonicalize(g.c_str()) + "_" + suffix; }

// Returns a canonicalized form of a local identifier's name, expanding its
// module prefix if needed.
std::string LocalName(const ID* l) const;
std::string LocalName(const IDPtr& l) const { return LocalName(l.get()); }

// The same, but for a capture.
std::string CaptureName(const ID* l) const;
std::string CaptureName(const IDPtr& l) const { return CaptureName(l.get()); }

// Returns a canonicalized name, with various non-alphanumeric characters
// stripped or transformed, and guaranteed not to conflict with C++ keywords.
std::string Canonicalize(const std::string& name) const;

// Returns the name of the global corresponding to an expression (which must
// be a EXPR_NAME).
std::string GlobalName(const ExprPtr& e) { return globals[e->AsNameExpr()->Id()->Name()]; }

// Globals that are used (appear in the profiles) of the bodies we're
// compiling. Includes globals just used as functions to call.
std::unordered_set<const ID*> all_accessed_globals;

// Same, but just the globals used in contexts beyond function calls.
std::unordered_set<const ID*> accessed_globals;

// Lambdas that are accessed.
std::unordered_set<const LambdaExpr*> accessed_lambdas;

// Events that are accessed.
std::unordered_set<std::string> accessed_events;

// Maps global names (not identifiers) to the names we use for them.
std::unordered_map<std::string, std::string> globals;

// Similar for locals, for the function currently being compiled.
std::unordered_map<const ID*, std::string> locals;

// Retrieves the initialization information associated with the given global.
std::unordered_map<const ID*, std::shared_ptr<CPP_InitInfo>> global_gis;

// Maps event names to the names we use for them.
std::unordered_map<std::string, std::string> events;

// Globals that correspond to variables, not functions.
IDSet global_vars;
