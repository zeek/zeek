// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeekygen/Target.h"

#include <fts.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <regex>

#include "zeek/Reporter.h"
#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/plugin/Manager.h"
#include "zeek/util.h"
#include "zeek/zeekygen/IdentifierInfo.h"
#include "zeek/zeekygen/Manager.h"
#include "zeek/zeekygen/PackageInfo.h"
#include "zeek/zeekygen/ScriptInfo.h"
#include "zeek/zeekygen/SpicyModuleInfo.h"

using namespace std;

namespace zeek::zeekygen::detail {

static void write_plugin_section_heading(FILE* f, const string& name, const string& description) {
    // A label-safe version of the plugin name: replace _ and : with -, turn
    // sequences of - into single ones, and make lower-case. Example:
    // "Zeek::IEEE802_11" -> "zeek-ieee802-11".
    auto flags = std::regex_constants::match_any;
    string label_name = std::regex_replace(name, std::regex("[_:]"), "-", flags);
    label_name = std::regex_replace(label_name, std::regex("-+"), "-", flags);
    label_name = zeek::util::strtolower(label_name);

    fprintf(f, ".. _plugin-%s:\n\n", label_name.c_str());

    fprintf(f, "%s\n", name.c_str());
    for ( size_t i = 0; i < name.size(); ++i )
        fprintf(f, "-");
    fprintf(f, "\n\n");

    fprintf(f, "%s\n\n", description.c_str());
}

static void write_analyzer_component(FILE* f, const analyzer::Component* c) {
    const auto& atag = analyzer_mgr->GetTagType();
    string tag = util::fmt("ANALYZER_%s", c->CanonicalName().c_str());

    if ( atag->Lookup("Analyzer", tag.c_str()) < 0 )
        reporter->InternalError("missing analyzer tag for %s", tag.c_str());

    fprintf(f, ":zeek:enum:`Analyzer::%s`\n\n", tag.c_str());
}

static void write_analyzer_component(FILE* f, const packet_analysis::Component* c) {
    const auto& atag = packet_mgr->GetTagType();
    string tag = util::fmt("ANALYZER_%s", c->CanonicalName().c_str());

    if ( atag->Lookup("PacketAnalyzer", tag.c_str()) < 0 )
        reporter->InternalError("missing packet analyzer tag for %s", tag.c_str());

    fprintf(f, ":zeek:enum:`PacketAnalyzer::%s`\n\n", tag.c_str());
}

static void write_analyzer_component(FILE* f, const file_analysis::Component* c) {
    const auto& atag = file_mgr->GetTagType();
    string tag = util::fmt("ANALYZER_%s", c->CanonicalName().c_str());

    if ( atag->Lookup("Files", tag.c_str()) < 0 )
        reporter->InternalError("missing analyzer tag for %s", tag.c_str());

    fprintf(f, ":zeek:enum:`Files::%s`\n\n", tag.c_str());
}

static void write_plugin_components(FILE* f, const plugin::Plugin::component_list& components) {
    fprintf(f, "Components\n");
    fprintf(f, "++++++++++\n\n");

    for ( const auto& component : components ) {
        switch ( component->Type() ) {
            case plugin::component::ANALYZER: {
                const analyzer::Component* c = dynamic_cast<const analyzer::Component*>(component);

                if ( c )
                    write_analyzer_component(f, c);
                else
                    reporter->InternalError("component type mismatch");
            } break;

            case plugin::component::PACKET_ANALYZER: {
                const packet_analysis::Component* c = dynamic_cast<const packet_analysis::Component*>(component);

                if ( c )
                    write_analyzer_component(f, c);
                else
                    reporter->InternalError("component type mismatch");
            } break;

            case plugin::component::FILE_ANALYZER: {
                const auto* c = dynamic_cast<const file_analysis::Component*>(component);

                if ( c )
                    write_analyzer_component(f, c);
                else
                    reporter->InternalError("component type mismatch");
            } break;

            case plugin::component::READER: reporter->InternalError("docs for READER component unimplemented");

            case plugin::component::WRITER: reporter->InternalError("docs for WRITER component unimplemented");

            default: reporter->InternalError("docs for unknown component unimplemented");
        }
    }
}

static void write_plugin_bif_items(FILE* f, plugin::Plugin::bif_item_list bifitems, plugin::BifItem::Type t,
                                   const string& heading) {
    plugin::Plugin::bif_item_list::iterator it = bifitems.begin();

    while ( it != bifitems.end() ) {
        if ( it->GetType() != t )
            it = bifitems.erase(it);
        else
            ++it;
    }

    if ( bifitems.empty() )
        return;

    fprintf(f, "%s\n", heading.c_str());
    for ( size_t i = 0; i < heading.size(); ++i )
        fprintf(f, "+");
    fprintf(f, "\n\n");

    for ( it = bifitems.begin(); it != bifitems.end(); ++it ) {
        IdentifierInfo* doc = zeek::detail::zeekygen_mgr->GetIdentifierInfo(it->GetID());

        if ( doc )
            fprintf(f, "%s\n\n", doc->ReStructuredText().c_str());
        else
            reporter->InternalWarning("Zeekygen ID lookup failed: %s\n", it->GetID().c_str());
    }
}

static void WriteAnalyzerTagDefn(FILE* f, const string& module) {
    string tag_id = module + "::Tag";

    IdentifierInfo* doc = zeek::detail::zeekygen_mgr->GetIdentifierInfo(tag_id);

    if ( ! doc )
        reporter->InternalError("Zeekygen failed analyzer tag lookup: %s", tag_id.c_str());

    fprintf(f, "%s\n", doc->ReStructuredText().c_str());
}

static bool ComponentsMatch(const plugin::Plugin::component_list& components, plugin::component::Type t,
                            bool match_empty = false) {
    plugin::Plugin::component_list::const_iterator it;

    if ( components.empty() )
        return match_empty;

    for ( it = components.begin(); it != components.end(); ++it )
        if ( (*it)->Type() != t )
            return false;

    return true;
}

template<class T>
static vector<T*> filter_matches(const vector<Info*>& from, Target* t) {
    vector<T*> rval;

    for ( Info* f : from ) {
        T* d = dynamic_cast<T*>(f);

        if ( ! d )
            continue;

        if ( t->MatchesPattern(d) ) {
            DBG_LOG(DBG_ZEEKYGEN, "'%s' matched pattern for target '%s'", d->Name().c_str(), t->Name().c_str());
            rval.push_back(d);
        }
    }

    return rval;
}

TargetFile::TargetFile(string arg_name) : name(std::move(arg_name)) {
    if ( name.find('/') != string::npos ) {
        string dir = util::SafeDirname(name).result;

        if ( ! util::detail::ensure_intermediate_dirs(dir.c_str()) )
            reporter->FatalError("Zeekygen failed to make dir %s", dir.c_str());
    }

    f = fopen(name.c_str(), "w");

    if ( ! f )
        reporter->FatalError("Zeekygen failed to open '%s' for writing: %s", name.c_str(), strerror(errno));
}

TargetFile::~TargetFile() {
    if ( f )
        fclose(f);

    DBG_LOG(DBG_ZEEKYGEN, "Wrote out-of-date target '%s'", name.c_str());
}

Target::Target(string arg_name, string arg_pattern)
    : name(std::move(arg_name)), pattern(std::move(arg_pattern)), prefix() {
    size_t pos = pattern.find('*');

    if ( pos == 0 || pos == string::npos )
        return;

    prefix = pattern.substr(0, pos);
}

bool Target::MatchesPattern(Info* info) const {
    if ( pattern == "*" )
        return true;

    if ( prefix.empty() )
        return info->Name() == pattern;

    return ! strncmp(info->Name().c_str(), prefix.c_str(), prefix.size());
}

void AnalyzerTarget::DoFindDependencies(const std::vector<Info*>& infos) {
    // TODO: really should add to dependency list the tag type's ID and
    // all bif items for matching analyzer plugins, but that's all dependent
    // on the Zeek binary itself, so I'm cheating.
}

void AnalyzerTarget::DoGenerate() const {
    if ( zeek::detail::zeekygen_mgr->IsUpToDate(Name(), vector<Info*>()) )
        return;

    if ( Pattern() != "*" )
        reporter->InternalWarning(
            "Zeekygen only implements analyzer target"
            " pattern '*'");

    TargetFile file(Name());
    CreateAnalyzerDoc(file.f);
}

void AnalyzerTarget::WriteAnalyzerElements(FILE* f, plugin::component::Type type, bool match_empty) const {
    // Create a union of the joint sets of all names provided by plugins and
    // Spicy analyzers.

    struct IgnoreCase {
        bool operator()(const std::string& a, const std::string& b) const {
            return util::strtolower(a) < util::strtolower(b);
        }
    };

    std::set<std::string, IgnoreCase> names;
    std::map<std::string, plugin::Plugin*> plugins;

    for ( auto p : plugin_mgr->ActivePlugins() ) {
        if ( ComponentsMatch(p->Components(), type, match_empty) ) {
            names.insert(p->Name());
            plugins[p->Name()] = p;
        }
    }

    auto spicy_modules = zeek::detail::zeekygen_mgr->SpicyModules();
    for ( const auto& [name, m] : spicy_modules ) {
        if ( ComponentsMatch(m->Components(), type, match_empty) )
            names.insert(name);
    }

    // Now output the information associated with each name in sorted order.
    for ( const auto& name : names ) {
        plugin::Plugin::bif_item_list bif_items;

        if ( auto i = plugins.find(name); i != plugins.end() ) // prefer built-in plugins over Spicy
                                                               // analyzer in case of name collision
        {
            auto plugin = i->second;
            write_plugin_section_heading(f, plugin->Name(), plugin->Description());

            if ( name != "Zeek::Spicy" ) // skip components (which are the available Spicy analyzers
                                         // documented separately).
                write_plugin_components(f, plugin->Components());

            bif_items = plugin->BifItems();
        }
        else {
            auto module = spicy_modules[name];
            write_plugin_section_heading(f, module->Name(), module->Description());
            write_plugin_components(f, module->Components());
            bif_items = module->BifItems();
        }

        write_plugin_bif_items(f, bif_items, plugin::BifItem::CONSTANT, "Options/Constants");
        write_plugin_bif_items(f, bif_items, plugin::BifItem::GLOBAL, "Globals");
        write_plugin_bif_items(f, bif_items, plugin::BifItem::TYPE, "Types");
        write_plugin_bif_items(f, bif_items, plugin::BifItem::EVENT, "Events");
        write_plugin_bif_items(f, bif_items, plugin::BifItem::FUNCTION, "Functions");
    }
}

void ProtoAnalyzerTarget::DoCreateAnalyzerDoc(FILE* f) const {
    fprintf(f, "Protocol Analyzers\n");
    fprintf(f, "==================\n\n");

    WriteAnalyzerTagDefn(f, "Analyzer");
    WriteAnalyzerTagDefn(f, "AllAnalyzers");

    WriteAnalyzerElements(f, plugin::component::ANALYZER, true);
}

void PacketAnalyzerTarget::DoCreateAnalyzerDoc(FILE* f) const {
    fprintf(f, "Packet Analyzers\n");
    fprintf(f, "================\n\n");

    WriteAnalyzerTagDefn(f, "PacketAnalyzer");

    WriteAnalyzerElements(f, plugin::component::PACKET_ANALYZER);
}

void FileAnalyzerTarget::DoCreateAnalyzerDoc(FILE* f) const {
    fprintf(f, "File Analyzers\n");
    fprintf(f, "==============\n\n");

    WriteAnalyzerTagDefn(f, "Files");

    WriteAnalyzerElements(f, plugin::component::FILE_ANALYZER);
}

void PackageTarget::DoFindDependencies(const vector<Info*>& infos) {
    pkg_deps = filter_matches<PackageInfo>(infos, this);

    if ( pkg_deps.empty() )
        reporter->FatalError("No match for Zeekygen target '%s' pattern '%s'", Name().c_str(), Pattern().c_str());

    for ( Info* info : infos ) {
        ScriptInfo* script = dynamic_cast<ScriptInfo*>(info);

        if ( ! script )
            continue;

        for ( const auto& dep : pkg_deps ) {
            if ( strncmp(script->Name().c_str(), dep->Name().c_str(), dep->Name().size()) != 0 )
                continue;

            DBG_LOG(DBG_ZEEKYGEN, "Script %s associated with package %s", script->Name().c_str(), dep->Name().c_str());
            pkg_manifest[dep].push_back(script);
            script_deps.push_back(script);
        }
    }
}

void PackageTarget::DoGenerate() const {
    if ( zeek::detail::zeekygen_mgr->IsUpToDate(Name(), script_deps) &&
         zeek::detail::zeekygen_mgr->IsUpToDate(Name(), pkg_deps) )
        return;

    TargetFile file(Name());

    fprintf(file.f, ":orphan:\n\n");

    for ( const auto& [pkg, info_vec] : pkg_manifest ) {
        string header = util::fmt("Package: %s", pkg->Name().c_str());
        auto header_size = header.size();
        header.append("\n");
        header.append(string(header_size, '='));

        fprintf(file.f, "%s\n\n", header.c_str());

        vector<string> readme = pkg->GetReadme();

        for ( const auto& r : readme )
            fprintf(file.f, "%s\n", r.c_str());

        fprintf(file.f, "\n");

        for ( ScriptInfo* info : info_vec ) {
            fprintf(file.f, ":doc:`/scripts/%s`\n\n", info->Name().c_str());

            vector<string> cmnts = info->GetComments();

            for ( const auto& cmnt : cmnts )
                fprintf(file.f, "   %s\n", cmnt.c_str());

            fprintf(file.f, "\n");
        }
    }
}

void PackageIndexTarget::DoFindDependencies(const vector<Info*>& infos) {
    pkg_deps = filter_matches<PackageInfo>(infos, this);

    if ( pkg_deps.empty() )
        reporter->FatalError("No match for Zeekygen target '%s' pattern '%s'", Name().c_str(), Pattern().c_str());
}

void PackageIndexTarget::DoGenerate() const {
    if ( zeek::detail::zeekygen_mgr->IsUpToDate(Name(), pkg_deps) )
        return;

    TargetFile file(Name());

    for ( PackageInfo* info : pkg_deps )
        fprintf(file.f, "%s\n", info->ReStructuredText().c_str());
}

void ScriptTarget::DoFindDependencies(const vector<Info*>& infos) {
    script_deps = filter_matches<ScriptInfo>(infos, this);

    if ( script_deps.empty() )
        reporter->FatalError("No match for Zeekygen target '%s' pattern '%s'", Name().c_str(), Pattern().c_str());

    if ( ! IsDir() )
        return;

    for ( ScriptInfo* d : script_deps ) {
        if ( util::detail::is_package_loader(d->Name()) ) {
            string pkg_dir = util::SafeDirname(d->Name()).result;
            string target_file = Name() + pkg_dir + "/index.rst";
            Target* t = new PackageTarget(target_file, pkg_dir);
            t->FindDependencies(infos);
            pkg_deps.push_back(t);
        }
    }
}

vector<string> dir_contents_recursive(string dir) {
    vector<string> rval;
    struct stat st;

    if ( stat(dir.c_str(), &st) < 0 && errno == ENOENT )
        return rval;

    while ( dir[dir.size() - 1] == '/' )
        dir.erase(dir.size() - 1, 1);

    char* scan_path[2] = {dir.data(), nullptr};

    FTS* fts = fts_open(scan_path, FTS_NOCHDIR, nullptr);

    if ( ! fts ) {
        reporter->Error("fts_open failure: %s", strerror(errno));
        return rval;
    }

    FTSENT* n;

    while ( (n = fts_read(fts)) ) {
        if ( n->fts_info & FTS_F )
            rval.emplace_back(n->fts_path);
    }

    if ( errno )
        reporter->Error("fts_read failure: %s", strerror(errno));

    if ( fts_close(fts) < 0 )
        reporter->Error("fts_close failure: %s", strerror(errno));

    return rval;
}

void ScriptTarget::DoGenerate() const {
    if ( IsDir() ) {
        // Target name is a dir, matching scripts are written within that dir
        // with a dir tree that parallels the script's ZEEKPATH location.

        set<string> targets;
        vector<string> dir_contents = dir_contents_recursive(Name());

        for ( ScriptInfo* d : script_deps ) {
            string target_filename = Name() + d->Name() + ".rst";
            targets.insert(target_filename);
            vector<ScriptInfo*> dep;
            dep.push_back(d);

            if ( zeek::detail::zeekygen_mgr->IsUpToDate(target_filename, dep) )
                continue;

            TargetFile file(std::move(target_filename));

            fprintf(file.f, "%s\n", d->ReStructuredText().c_str());
        }

        for ( Target* tgt : pkg_deps ) {
            targets.insert(tgt->Name());
            tgt->Generate();
        }

        for ( const auto& f : dir_contents ) {
            if ( targets.find(f) != targets.end() )
                continue;

            if ( unlink(f.c_str()) < 0 )
                reporter->Warning("Failed to unlink %s: %s", f.c_str(), strerror(errno));

            DBG_LOG(DBG_ZEEKYGEN, "Delete stale script file %s", f.c_str());
        }

        return;
    }

    // Target is a single file, all matching scripts get written there.

    if ( zeek::detail::zeekygen_mgr->IsUpToDate(Name(), script_deps) )
        return;

    TargetFile file(Name());

    for ( ScriptInfo* d : script_deps ) {
        fprintf(file.f, "%s\n", d->ReStructuredText().c_str());
    }
}

void ScriptSummaryTarget::DoGenerate() const {
    if ( zeek::detail::zeekygen_mgr->IsUpToDate(Name(), script_deps) )
        return;

    TargetFile file(Name());

    for ( ScriptInfo* d : script_deps ) {
        if ( ! d )
            continue;

        fprintf(file.f, ":doc:`/scripts/%s`\n", d->Name().c_str());

        vector<string> cmnts = d->GetComments();

        for ( const string& cmnt : cmnts )
            fprintf(file.f, "    %s\n", cmnt.c_str());

        fprintf(file.f, "\n");
    }
}

void ScriptIndexTarget::DoGenerate() const {
    if ( zeek::detail::zeekygen_mgr->IsUpToDate(Name(), script_deps) )
        return;

    TargetFile file(Name());

    fprintf(file.f, ".. toctree::\n");
    fprintf(file.f, "   :maxdepth: 1\n\n");

    for ( ScriptInfo* d : script_deps ) {
        if ( ! d )
            continue;

        fprintf(file.f, "   %s </scripts/%s>\n", d->Name().c_str(), d->Name().c_str());
    }
}

void IdentifierTarget::DoFindDependencies(const vector<Info*>& infos) {
    id_deps = filter_matches<IdentifierInfo>(infos, this);

    if ( id_deps.empty() )
        reporter->FatalError("No match for Zeekygen target '%s' pattern '%s'", Name().c_str(), Pattern().c_str());
}

void IdentifierTarget::DoGenerate() const {
    if ( zeek::detail::zeekygen_mgr->IsUpToDate(Name(), id_deps) )
        return;

    TargetFile file(Name());

    for ( IdentifierInfo* info : id_deps )
        fprintf(file.f, "%s\n\n", info->ReStructuredText().c_str());
}

} // namespace zeek::zeekygen::detail
