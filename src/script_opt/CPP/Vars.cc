// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/Compile.h"
#include "zeek/script_opt/IDOptInfo.h"

namespace zeek::detail {

using namespace std;

bool CPPCompile::CreateGlobal(IDPtr g) {
    auto gn = string(g->Name());
    bool is_bif = pfs->BiFGlobals().contains(g);

    if ( ! accessed_globals.contains(g) ) {
        // Only used in the context of calls.  If it's compilable,
        // then we'll call it directly.
        if ( compilable_funcs.contains(gn) ) {
            AddGlobal(gn, "zf");
            return false;
        }

        if ( is_bif ) {
            AddBiF(g, false);
            return false;
        }
    }

    bool should_init = false;

    if ( AddGlobal(gn, "gl") ) { // We'll be creating this global.
        Emit("IDPtr %s;", globals[gn]);

        if ( accessed_events.contains(gn) )
            // This is an event that's also used as a variable.
            Emit("EventHandlerPtr %s_ev;", globals[gn]);

        should_init = true;
    }

    if ( is_bif )
        // This is a BiF that's referred to in a non-call context,
        // so we didn't already add it above.
        AddBiF(g, true);

    global_vars.emplace(g);

    return should_init;
}

std::shared_ptr<CPP_InitInfo> CPPCompile::RegisterGlobal(IDPtr g) {
    auto gg = global_gis.find(g);

    if ( gg != global_gis.end() )
        return gg->second;

    auto gn = string(g->Name());

    if ( ! globals.contains(gn) ) {
        // Create a name for it.
        (void)IDNameStr(g);

        // That call may have created the initializer, in which
        // case no need to repeat it.
        gg = global_gis.find(g);
        if ( gg != global_gis.end() )
            return gg->second;
    }

    auto gi = GenerateGlobalInit(g);
    global_id_info->AddInstance(gi);
    global_gis[g] = gi;

    return gi;
}

std::shared_ptr<CPP_InitInfo> CPPCompile::GenerateGlobalInit(IDPtr g) {
    auto gn = string(g->Name());
    if ( ! standalone )
        return make_shared<GlobalLookupInitInfo>(this, g, globals[gn]);

    if ( obj_matches_opt_files(g) == AnalyzeDecision::SHOULD )
        return make_shared<GlobalInitInfo>(this, g, globals[gn]);

    // It's not a global that's created by the scripts we're compiling,
    // but it might have a redef in those scripts, in which case we need
    // to generate an initializer that will both look it up and then assign
    // it to that value.
    bool needs_redef = false;

    for ( const auto& i_e : g->GetOptInfo()->GetInitExprs() )
        if ( obj_matches_opt_files(i_e) == AnalyzeDecision::SHOULD ) {
            needs_redef = true;
            break;
        }

    return make_shared<GlobalLookupInitInfo>(this, g, globals[gn], needs_redef);
}

void CPPCompile::AddBiF(IDPtr b, bool is_var) {
    auto bn = b->Name();
    auto n = string(bn);
    if ( is_var )
        n = n + "_"; // make the name distinct

    if ( AddGlobal(n, "bif") )
        Emit("Func* %s;", globals[n]);

    ASSERT(! BiFs.contains(globals[n]));
    BiFs[globals[n]] = bn;
}

bool CPPCompile::AddGlobal(const string& g, const char* suffix) {
    if ( globals.contains(g) )
        return false;

    globals.emplace(g, GlobalName(g, suffix));
    return true;
}

void CPPCompile::RegisterEvent(string ev_name) { body_events[body_name].emplace_back(std::move(ev_name)); }

const string& CPPCompile::IDNameStr(const IDPtr& id) {
    if ( id->IsGlobal() ) {
        auto g = string(id->Name());
        if ( ! globals.contains(g) )
            CreateGlobal(id);
        return globals[g];
    }

    auto l = locals.find(id);
    ASSERT(l != locals.end());
    return l->second;
}

static string trim_name(const IDPtr& id) {
    auto n = id->Name();
    auto without_module = strstr(n, "::");

    while ( without_module ) {
        n = without_module + 2;
        without_module = strstr(n, "::");
    }

    string ns = n;

    // Look for suffices added by check_params() (src/Var.cc).
    static auto hidden_suffix = "-hidden";
    static auto hidden_suffix_len = strlen(hidden_suffix);
    auto hidden_loc = ns.find(hidden_suffix);

    if ( hidden_loc != string::npos )
        ns.erase(hidden_loc, hidden_loc + hidden_suffix_len);

    return ns;
}

string CPPCompile::LocalName(const IDPtr& l) const { return Canonicalize(trim_name(l)); }

string CPPCompile::CaptureName(const IDPtr& c) const {
    // We want to strip both the module and any inlining appendage.
    auto tn = trim_name(c);

    auto appendage = tn.find('.');
    if ( appendage != string::npos )
        tn.erase(tn.begin() + appendage, tn.end());

    return Canonicalize(tn);
}

string CPPCompile::Canonicalize(const std::string& name) const {
    string cname;

    for ( auto c : name ) {
        // Strip <>'s - these get introduced for lambdas.
        if ( c == '<' || c == '>' )
            continue;

        if ( c == ':' || c == '-' || c == '.' )
            c = '_';

        cname += c;
    }

    // Add a trailing '_' to avoid conflicts with C++ keywords.
    return cname + "_";
}

} // namespace zeek::detail
