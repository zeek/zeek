// See the file "COPYING" in the main distribution directory for copyright.

// Methods for generating run-time initialization of objects relating to
// Zeek values and types.
//
// This file is included by Compile.h to insert into the CPPCompiler class.

public:
// True if the given expression is simple enough that we can generate code
// to evaluate it directly, and don't need to create a separate function per
// RegisterInitExpr() to track it.
static bool IsSimpleInitExpr(const ExprPtr& e);

// Easy access to the global offset and the initialization
// cohort associated with a given type.
int TypeOffset(const TypePtr& t) { return GI_Offset(RegisterType(t)); }
int TypeCohort(const TypePtr& t) { return GI_Cohort(RegisterType(t)); }
int TypeFinalCohort(const TypePtr& t) { return GI_FinalCohort(RegisterType(t)); }

// Tracks expressions used in attributes (such as &default=<expr>).
//
// We need to generate code to evaluate these, via CallExpr's that invoke
// functions that return the value of the expression.  However, we can't
// generate that code when first encountering the attribute, because doing
// so will need to refer to the names of types, and initially those are
// unavailable (because the type's representatives, per pfs->RepTypes(), might
// not have yet been tracked).  So instead we track the associated
// CallExprInitInfo objects, and after all types have been tracked, then spin
// through them to generate the code.
//
// Returns the associated initialization information.
std::shared_ptr<CPP_InitInfo> RegisterInitExpr(const ExprPtr& e);

// Tracks a C++ string value needed for initialization.  Returns
// an offset into the global vector that will hold these.
int TrackString(const std::string& s) {
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
int TrackHash(p_hash_type h) {
    auto th = tracked_hashes.find(h);
    if ( th != tracked_hashes.end() )
        return th->second;

    int offset = ordered_tracked_hashes.size();
    tracked_hashes[h] = offset;
    ordered_tracked_hashes.emplace_back(h);

    return offset;
}

private:
// Generates code for dynamically generating an expression associated with an
// attribute, via a function call.
void GenInitExpr(const std::shared_ptr<CallExprInitInfo>& ce_init);

// Returns the name of a function used to evaluate an initialization expression.
std::string InitExprName(const ExprPtr& e);

// Convenience functions for returning the offset or initialization cohort
// associated with an initialization.
int GI_Offset(const std::shared_ptr<CPP_InitInfo>& gi) const { return gi ? gi->Offset() : -1; }
int GI_Cohort(const std::shared_ptr<CPP_InitInfo>& gi) const { return gi ? gi->InitCohort() : 0; }
int GI_FinalCohort(const std::shared_ptr<CPP_InitInfo>& gi) const { return gi ? gi->FinalInitCohort() : 0; }

// Generate code to initialize the mappings for record field offsets for field
// accesses into regions of records that can be extensible (and thus can vary
// at run-time to the offsets encountered during compilation).
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

// Generate code to initialize a global (using dynamic statements rather than
// constants).
void InitializeGlobal(const IDPtr& g);

// Generate code to initialize globals (using dynamic statements rather than
// constants).
void InitializeGlobals();

// Generate the initialization hook for this set of compiled code.
void GenInitHook();

// Generates code to activate standalone code.
void GenStandaloneActivation();

// Generates code to register the initialization for standalone use, and
// prints to stdout a Zeek script that can load all of what we compiled.
void GenLoad();

// A list of BiFs to look up during initialization.  First string is the name
// of the C++ global holding the BiF, the second is its name as known to Zeek.
std::unordered_map<std::string, std::string> BiFs;

// Expressions for which we need to generate initialization-time code.
// Currently, these are only expressions appearing in attributes.
CPPTracker<Expr> init_exprs = {"gen_init_expr", false};

// Maps strings to associated offsets.
std::unordered_map<std::string, int> tracked_strings;

// Tracks strings we've registered in order (corresponding to
// their offsets).
std::vector<std::string> ordered_tracked_strings;

// The same as the previous two, but for profile hashes.
std::vector<p_hash_type> ordered_tracked_hashes;
std::unordered_map<p_hash_type, int> tracked_hashes;
