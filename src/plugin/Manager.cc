// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Manager.h"

#include <dirent.h>
#ifndef _MSC_VER
#include <dlfcn.h>
#include <glob.h>
#endif
#ifdef _MSC_VER
#include <windows.h>
#endif
#include <sys/stat.h>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <ranges>
#include <regex>
#include <sstream>

#include "zeek/Event.h"
#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/input.h"
#include "zeek/util.h"

using namespace std;

namespace zeek::plugin {

Plugin* Manager::current_plugin = nullptr;
const char* Manager::current_dir = nullptr;
const char* Manager::current_sopath = nullptr;

Manager::Manager() {
    init = false;
    hooks = new hook_list*[NUM_HOOKS];

    for ( int i = 0; i < NUM_HOOKS; i++ )
        hooks[i] = nullptr;
}

Manager::~Manager() {
    assert(! init);

    for ( int i = 0; i < NUM_HOOKS; i++ )
        delete hooks[i];

    delete[] hooks;
}

void Manager::SearchDynamicPlugins(const std::string& dir) {
    assert(! init);

    if ( dir.empty() )
        return;

    if ( dir.find(path_list_separator) != string::npos ) {
        // Split at ":".
        std::stringstream s(dir);
        std::string d;

        while ( std::getline(s, d, path_list_separator[0]) )
            SearchDynamicPlugins(d);

        return;
    }

    if ( ! util::is_dir(dir) ) {
        DBG_LOG(DBG_PLUGINS, "Not a valid plugin directory: %s", dir.c_str());
        return;
    }

    std::error_code ec;
    auto canon = filesystem::canonical(dir, ec);
    if ( ec ) {
        DBG_LOG(DBG_PLUGINS, "skip dynamic plugin search in %s, making path canonical failed: %s", dir.data(),
                ec.message().c_str());
        return;
    }

    std::string canon_path = canon.string();

    if ( searched_dirs.contains(canon_path) )
        return;

    searched_dirs.emplace(canon_path);

    // Check if it's a plugin directory.

    const std::string magic = dir + "/__zeek_plugin__";

    if ( util::is_file(magic) ) {
        // It's a plugin, get it's name.
        std::ifstream in(magic.c_str());

        if ( in.fail() )
            reporter->FatalError("cannot open plugin magic file %s", magic.c_str());

        std::string name;
        std::getline(in, name);
        util::strstrip(name);
        string lower_name = util::strtolower(name);

        if ( name.empty() )
            reporter->FatalError("empty plugin magic file %s", magic.c_str());

        if ( const auto& other = dynamic_plugins.find(lower_name); other != dynamic_plugins.end() ) {
            reporter->Warning("ignoring dynamic plugin %s from %s, already found in %s", name.c_str(), dir.c_str(),
                              other->second.c_str());
            return;
        }

        // Record it, so that we can later activate it.
        dynamic_plugins.insert(std::make_pair(lower_name, dir));

        DBG_LOG(DBG_PLUGINS, "Found plugin %s in %s", name.c_str(), dir.c_str());
        return;
    }

    // No plugin here, traverse subdirectories.

    DIR* d = opendir(dir.c_str());

    if ( ! d ) {
        DBG_LOG(DBG_PLUGINS, "Cannot open directory %s", dir.c_str());
        return;
    }

    bool found = false;

    struct dirent* dp;

    while ( (dp = readdir(d)) ) {
        struct stat st;

        if ( strcmp(dp->d_name, "..") == 0 || strcmp(dp->d_name, ".") == 0 )
            continue;

        // We do not search plugins in discovered dot directories.
        if ( (dp->d_name[0] == '.') && dp->d_type == DT_DIR )
            continue;

        string path = dir + "/" + dp->d_name;

        if ( stat(path.c_str(), &st) < 0 ) {
            DBG_LOG(DBG_PLUGINS, "Cannot stat %s: %s", path.c_str(), strerror(errno));
            continue;
        }

        if ( st.st_mode & S_IFDIR )
            SearchDynamicPlugins(path);
    }

    closedir(d);
}

zeek::expected<Plugin*, std::string> Manager::LoadDynamicPlugin(const std::string& path) {
    DBG_LOG(DBG_PLUGINS, "Loading plugin %s", path.c_str());

    current_plugin = nullptr;
    current_sopath = path.c_str();

#ifdef _MSC_VER
    HMODULE hdl = LoadLibraryA(path.c_str());
    current_sopath = nullptr;

    if ( ! hdl ) {
        DWORD err_code = GetLastError();
        char buf[512] = {};
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, err_code, 0, buf,
                       sizeof(buf), nullptr);
        // FormatMessageA appends \r\n — strip trailing whitespace.
        size_t len = strlen(buf);
        while ( len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n' || buf[len - 1] == ' ') )
            buf[--len] = '\0';
        std::string error = util::fmt("cannot load plugin library %s: %s (error %lu)", path.c_str(), buf, err_code);
        return zeek::unexpected<std::string>(std::move(error));
    }

    if ( ! current_plugin ) {
        std::string error = util::fmt("load plugin library %s did not instantiate a plugin", path.c_str());
        FreeLibrary(hdl);
        return zeek::unexpected<std::string>(std::move(error));
    }
#else
    void* hdl = dlopen(path.c_str(), RTLD_NOW | RTLD_GLOBAL);
    current_sopath = nullptr;

    if ( ! hdl ) {
        const char* err = dlerror();
        std::string error = util::fmt("cannot load plugin library %s: %s", path.c_str(), err ? err : "<unknown error>");
        return zeek::unexpected<std::string>(std::move(error));
    }

    if ( ! current_plugin ) {
        std::string error = util::fmt("load plugin library %s did not instantiate a plugin", path.c_str());
        dlclose(hdl);
        return zeek::unexpected<std::string>(std::move(error));
    }
#endif

    auto* plugin = current_plugin;
    current_plugin = nullptr;

    // This is a bit quirky: If we go through ActivateDynamicPluginInternal(),
    // its logic sets current_dir to a classic plugin's top-level directory,
    // also called base_dir. Concretely, Plugin::Plugin() -> Manager::RegisterPlugin()
    // -> Plugin::SetPluginPath() populates the plugin's base_dir and sopath members.
    //
    // If a plugin is loaded via @load ./plugin.so, there's no classic base_dir.
    // Manager::RegisterPlugin() will skip setting the paths on the plugin. We
    // recognize this here and set only the sopath. A plugin loaded via
    // @load ./plugin.so can be identified by an empty PluginDirectory(), but
    // having a populated PluginPath(), though hopefully this never matters.
    if ( plugin->PluginPath().empty() )
        plugin->SetPluginLocation("", path);

    plugin->SetDynamic(true);
    plugin->DoConfigure();

    // After Configure(), we'll have a name. Do not allow plugins with duplicate names:
    // Just consider that a conflict and hard-exit: All bets are off. Note that
    // the just loaded plugin is already part of ActivePluginsInternal().
    std::string plugin_name = util::strtolower(plugin->Name());
    for ( const auto* p : *Manager::ActivePluginsInternal() ) {
        if ( util::strtolower(p->Name()) == plugin_name && p != plugin )
            zeek::reporter->FatalError("plugin with name %s from %s conflicts with %s plugin %s",
                                       plugin->Name().c_str(), path.c_str(),
                                       p->DynamicPlugin() ? "dynamic" : "built-in", p->Name().c_str());
    }

    DBG_LOG(DBG_PLUGINS, "  InitializingComponents");
    plugin->InitializeComponents();

    // We execute the pre-script initialization here; this in
    // fact could be *during* script initialization if we got
    // triggered via @load-plugin or @load.
    plugin->InitPreScript();

    DBG_LOG(DBG_PLUGINS, "  Loaded %s", path.c_str());

    return plugin;
}

bool Manager::ActivateDynamicPluginInternal(const std::string& name, bool ok_if_not_found,
                                            std::vector<std::string>* errors) {
    errors->clear(); // caller should pass it in empty, but just to be sure

    dynamic_plugin_map::iterator m = dynamic_plugins.find(util::strtolower(name));

    plugin_list* all_plugins = Manager::ActivePluginsInternal();

    if ( m == dynamic_plugins.end() ) {
        if ( ok_if_not_found )
            return true;

        // Check if it's a static built-in plugin; they are always
        // active, so just ignore. Not the most efficient way, but
        // this should be rare to begin with.
        for ( const auto& p : *all_plugins ) {
            if ( p->Name() == name )
                return true;
        }

        errors->emplace_back(util::fmt("plugin %s is not available", name.c_str()));
        return false;
    }

    if ( m->second.empty() ) {
        // That's our marker that we have already activated this
        // plugin. Silently ignore the new request.
        return true;
    }

    std::string dir = m->second + "/";

    DBG_LOG(DBG_PLUGINS, "Activating plugin %s", name.c_str());

    // If there's a plugin with the same name already, report an error and let
    // the user do the conflict resolution.
    auto lower_name = util::strtolower(name);
    for ( const auto& p : *all_plugins ) {
        if ( util::strtolower(p->Name()) == lower_name ) {
            auto v = p->Version();
            auto error = util::fmt("dynamic plugin %s from directory %s conflicts with %s plugin %s (%d.%d.%d)",
                                   name.c_str(), dir.c_str(), p->DynamicPlugin() ? "dynamic" : "built-in",
                                   p->Name().c_str(), v.major, v.minor, v.patch);
            errors->emplace_back(error);
            return false;
        }
    }

    // Load shared libraries.

    string dypattern = dir + "/lib/*." + HOST_ARCHITECTURE + DYNAMIC_PLUGIN_SUFFIX;

    DBG_LOG(DBG_PLUGINS, "  Searching for shared libraries %s", dypattern.c_str());

#ifdef _MSC_VER
    // On Windows, use std::filesystem to find matching plugin DLLs
    // since glob() is not available.
    {
        std::string suffix = std::string(".") + HOST_ARCHITECTURE + DYNAMIC_PLUGIN_SUFFIX;
        std::string lib_dir = dir + "lib";
        bool found_libs = false;

        std::error_code ec;
        if ( std::filesystem::is_directory(lib_dir, ec) ) {
            for ( const auto& entry : std::filesystem::directory_iterator(lib_dir, ec) ) {
                if ( ! entry.is_regular_file() )
                    continue;

                auto fname = entry.path().filename().string();
                if ( fname.ends_with(suffix) ) {
                    found_libs = true;
                    auto path_str = entry.path().string();

                    current_dir = dir.c_str();
                    auto result = LoadDynamicPlugin(path_str);

                    if ( ! result ) {
                        errors->emplace_back(result.error());
                        continue;
                    }

                    auto* loaded_plugin = *result;

                    plugins_by_path.insert(std::make_pair(util::detail::normalize_path(dir), loaded_plugin));

                    // Make sure the name the plugin reports is consistent with
                    // what we expect from its magic file.
                    if ( util::strtolower(loaded_plugin->Name()) != util::strtolower(name) ) {
                        errors->emplace_back(util::fmt("inconsistent plugin name: %s vs %s",
                                                       loaded_plugin->Name().c_str(), name.c_str()));
                        continue;
                    }
                }
            }
        }

        if ( ! found_libs )
            DBG_LOG(DBG_PLUGINS, "  No shared library found");

        if ( ! errors->empty() )
            return false;
    }
#else
    glob_t gl;

    if ( glob(dypattern.c_str(), 0, nullptr, &gl) == 0 ) {
        for ( size_t i = 0; i < gl.gl_pathc; i++ ) {
            const char* path = gl.gl_pathv[i];

            current_dir = dir.c_str();
            auto result = LoadDynamicPlugin(path);

            if ( ! result ) {
                errors->emplace_back(result.error());
                continue;
            }

            auto* loaded_plugin = *result;

            plugins_by_path.insert(std::make_pair(util::detail::normalize_path(dir), loaded_plugin));

            // Make sure the name the plugin reports is consistent with
            // what we expect from its magic file.
            if ( util::strtolower(loaded_plugin->Name()) != util::strtolower(name) ) {
                errors->emplace_back(
                    util::fmt("inconsistent plugin name: %s vs %s", loaded_plugin->Name().c_str(), name.c_str()));
                continue;
            }
        }

        globfree(&gl);

        if ( ! errors->empty() )
            return false;
    }

    else {
        DBG_LOG(DBG_PLUGINS, "  No shared library found");
    }
#endif

    // Add the "scripts" and "bif" directories to ZEEKPATH.
    std::string scripts = dir + "scripts";

    if ( util::is_dir(scripts) ) {
        DBG_LOG(DBG_PLUGINS, "  Adding %s to ZEEKPATH", scripts.c_str());
        util::detail::add_to_zeek_path(scripts);
    }

    string init;

    // First load {scripts}/__preload__.zeek automatically.
    init = dir + "scripts/__preload__.zeek";

    if ( util::is_file(init) ) {
        DBG_LOG(DBG_PLUGINS, "  Loading %s", init.c_str());
        scripts_to_load.push_back(std::move(init));
    }

    // Load {bif,scripts}/__load__.zeek automatically.
    init = dir + "lib/bif/__load__.zeek";

    if ( util::is_file(init) ) {
        DBG_LOG(DBG_PLUGINS, "  Loading %s", init.c_str());
        scripts_to_load.push_back(std::move(init));
    }

    init = dir + "scripts/__load__.zeek";

    if ( util::is_file(init) ) {
        DBG_LOG(DBG_PLUGINS, "  Loading %s", init.c_str());
        scripts_to_load.push_back(std::move(init));
    }

    // Mark this plugin as activated by clearing the path.
    m->second.clear();

    return true;
}

void Manager::ActivateDynamicPlugin(const std::string& name) {
    std::vector<std::string> errors;
    if ( ActivateDynamicPluginInternal(name, false, &errors) )
        UpdateInputFiles();
    else
        // Reschedule for another attempt later.
        requested_plugins.insert(name);
}

void Manager::ActivateDynamicPlugins(bool all) {
    // Tracks plugins we need to activate as pairs of their names and booleans
    // indicating whether an activation failure is to be deemed a fatal error.
    std::set<std::pair<std::string, bool>> plugins_to_activate;

    // Activate plugins that were specifically requested.
    for ( const auto& x : requested_plugins ) {
        if ( ! x.empty() )
            plugins_to_activate.emplace(x, false);
    }

    // Activate plugins that our environment tells us to.
    vector<string> p;
    std::string plugin_activate = util::zeek_plugin_activate();
    if ( ! plugin_activate.empty() ) {
        util::tokenize_string(util::zeek_plugin_activate(), ",", &p);

        for ( const auto& x : p )
            plugins_to_activate.emplace(x, true);
    }

    if ( all ) {
        // Activate all other ones we discovered.
        for ( const auto& x : dynamic_plugins )
            plugins_to_activate.emplace(x.first, false);
    }

    // Now we keep iterating over all the plugins, trying to load them, for as
    // long as we're successful for at least one further of them each round.
    // Doing so ensures that we can resolve (non-cyclic) load dependencies
    // independent of any particular order.
    while ( ! plugins_to_activate.empty() ) {
        std::vector<std::string> errors;
        auto plugins_left = plugins_to_activate;

        for ( const auto& x : plugins_to_activate ) {
            if ( ActivateDynamicPluginInternal(x.first, x.second, &errors) )
                plugins_left.erase(x);
        }

        if ( plugins_left.size() == plugins_to_activate.size() ) {
            // Could not load a single further plugin this round, that's fatal.
            for ( const auto& msg : errors )
                reporter->Error("%s", msg.c_str());

            reporter->FatalError("aborting after plugin errors");
        }

        plugins_to_activate = std::move(plugins_left);
    }

    UpdateInputFiles();
}

void Manager::UpdateInputFiles() {
    for ( const auto& script : std::ranges::reverse_view(scripts_to_load) )
        add_input_file_at_front(script.c_str());

    scripts_to_load.clear();
}

static bool plugin_cmp(const Plugin* a, const Plugin* b) {
    return util::strtolower(a->Name()) < util::strtolower(b->Name());
}

void Manager::RegisterPlugin(Plugin* plugin) {
    Manager::ActivePluginsInternal()->push_back(plugin);

    if ( current_dir && current_sopath )
        // A dynamic plugin, record its location.
        plugin->SetPluginLocation(util::detail::normalize_path(current_dir), current_sopath);

    current_plugin = plugin;
}

void Manager::RegisterBifFile(const char* plugin, bif_init_func c) {
    bif_init_func_map* bifs = BifFilesInternal();

    std::string lower_plugin = util::strtolower(plugin);
    bif_init_func_map::iterator i = bifs->find(lower_plugin);

    if ( i == bifs->end() )
        i = bifs->insert(std::make_pair(lower_plugin, new bif_init_func_list())).first;

    i->second->push_back(c);
}

void Manager::ExtendZeekPathForPlugins() {
    // Extend the path outside of the loop to avoid looking through a longer path for each plugin
    vector<string> path_additions;

    for ( const auto& p : Manager::ActivePlugins() ) {
        if ( p->DynamicPlugin() || p->Name().empty() )
            continue;

        try {
            string canon = std::regex_replace(p->Name(), std::regex("::"), "_");
            string dir = "builtin-plugins/" + canon;

            // Use find_file to find the directory in the path.
            string script_dir = util::find_file(dir, util::zeek_path());
            if ( script_dir.empty() || ! util::is_dir(script_dir) )
                continue;

            DBG_LOG(DBG_PLUGINS, "  Adding %s to ZEEKPATH", script_dir.c_str());
            path_additions.push_back(std::move(script_dir));
        } catch ( const std::regex_error& e ) {
            // This really shouldn't ever happen, but we do need to catch the exception.
            // Report a fatal error because something is wrong if this occurs.
            reporter->FatalError("Failed to replace colons in plugin name %s: %s", p->Name().c_str(), e.what());
        }
    }

    for ( const auto& plugin_path : path_additions )
        util::detail::add_to_zeek_path(plugin_path);
}

void Manager::InitPreScript() {
    assert(! init);

    for ( Plugin* plugin : *Manager::ActivePluginsInternal() ) {
        plugin->DoConfigure();
    }

    // Sort plugins by name to make sure we have a deterministic order.
    // We cannot do this before, because the plugin name (used for plugin_cmp) is only
    // set in DoConfigure.
    // We need things sorted to generate the tags (in InitializeComponents) in a deterministic
    // order.
    ActivePluginsInternal()->sort(plugin_cmp);

    for ( Plugin* plugin : *Manager::ActivePluginsInternal() ) {
        plugin->InitializeComponents();
        plugin->InitPreScript();
    }

    init = true;
}

void Manager::InitBifs() {
    bif_init_func_map* bifs = BifFilesInternal();

    for ( Plugin* plugin : *Manager::ActivePluginsInternal() ) {
        bif_init_func_map::const_iterator b = bifs->find(util::strtolower(plugin->Name()));

        if ( b != bifs->end() ) {
            for ( const auto& func : *(b->second) )
                func(plugin);
        }
    }
}

void Manager::InitPostScript() {
    assert(init);

    for ( Plugin* plugin : *Manager::ActivePluginsInternal() )
        plugin->InitPostScript();
}

void Manager::InitPreExecution() {
    assert(init);

    for ( Plugin* plugin : *Manager::ActivePluginsInternal() )
        plugin->InitPreExecution();
}

void Manager::FinishPlugins() {
    assert(init);

    for ( Plugin* plugin : *Manager::ActivePluginsInternal() )
        plugin->Done();

    Manager::ActivePluginsInternal()->clear();

    init = false;
}

Manager::plugin_list Manager::ActivePlugins() const { return *Manager::ActivePluginsInternal(); }

Manager::inactive_plugin_list Manager::InactivePlugins() const {
    plugin_list* all = ActivePluginsInternal();

    inactive_plugin_list inactives;

    for ( const auto& [index, plugin] : dynamic_plugins ) {
        bool found = false;

        for ( Plugin* plugin : *all ) {
            if ( index == util::strtolower(plugin->Name()) ) {
                found = true;
                break;
            }
        }

        if ( ! found )
            inactives.emplace_back(index, plugin);
    }

    return inactives;
}

Manager::plugin_list* Manager::ActivePluginsInternal() {
    static plugin_list* plugins = nullptr;

    if ( ! plugins )
        plugins = new plugin_list;

    return plugins;
}

Manager::bif_init_func_map* Manager::BifFilesInternal() {
    static bif_init_func_map* bifs = nullptr;

    if ( ! bifs )
        bifs = new bif_init_func_map;

    return bifs;
}

Plugin* Manager::LookupPluginByPath(std::string_view _path) {
    auto path = util::detail::normalize_path(_path);

    if ( util::is_file(path) )
        path = util::SafeDirname(path).result;

    while ( ! path.empty() ) {
        auto i = plugins_by_path.find(path);

        if ( i != plugins_by_path.end() )
            return i->second;

        auto j = path.rfind('/');

        if ( j == std::string::npos )
            break;

        path.erase(j);
    }

    return nullptr;
}

static bool hook_cmp(std::pair<int, Plugin*> a, std::pair<int, Plugin*> b) {
    if ( a.first == b.first )
        return util::strtolower(a.second->Name()) < util::strtolower(b.second->Name());

    // Reverse sort.
    return a.first > b.first;
}

std::list<std::pair<HookType, int>> Manager::HooksEnabledForPlugin(const Plugin* plugin) const {
    std::list<std::pair<HookType, int>> enabled;

    for ( int i = 0; i < NUM_HOOKS; i++ ) {
        if ( hook_list* l = hooks[i] )
            for ( const auto& [hook, hook_plugin] : *l )
                if ( hook_plugin == plugin )
                    enabled.emplace_back(static_cast<HookType>(i), hook);
    }

    return enabled;
}

void Manager::EnableHook(HookType hook, Plugin* plugin, int prio) {
    if ( ! hooks[hook] )
        hooks[hook] = new hook_list;

    hook_list* l = hooks[hook];

    for ( const auto& [_, hook_plugin] : *l ) {
        // Already enabled for this plugin.
        if ( hook_plugin == plugin )
            return;
    }

    l->emplace_back(prio, plugin);
    l->sort(hook_cmp);
}

void Manager::DisableHook(HookType hook, Plugin* plugin) {
    hook_list* l = hooks[hook];

    if ( ! l )
        return;

    for ( hook_list::iterator i = l->begin(); i != l->end(); i++ ) {
        if ( (*i).second == plugin ) {
            l->erase(i);
            break;
        }
    }

    if ( l->empty() ) {
        delete l;
        hooks[hook] = nullptr;
    }
}

void Manager::RequestEvent(EventHandlerPtr handler, Plugin* plugin) {
    DBG_LOG(DBG_PLUGINS, "Plugin %s requested event %s", plugin->Name().c_str(), handler->Name());
    handler->SetGenerateAlways();
}

void Manager::RequestObjDtor(Obj* obj, Plugin* plugin) { obj->NotifyPluginsOnDtor(); }

int Manager::HookLoadFile(const Plugin::LoadType type, const string& file, const string& resolved) {
    HookArgumentList args;

    if ( HavePluginForHook(META_HOOK_PRE) ) {
        args.emplace_back(type);
        args.emplace_back(file);
        args.emplace_back(resolved);
        MetaHookPre(HOOK_LOAD_FILE, args);
    }

    hook_list* l = hooks[HOOK_LOAD_FILE];

    int rc = -1;

    if ( l )
        for ( const auto& [_, p] : *l ) {
            rc = p->HookLoadFile(type, file, resolved);

            if ( rc >= 0 )
                break;
        }

    if ( HavePluginForHook(META_HOOK_POST) )
        MetaHookPost(HOOK_LOAD_FILE, args, HookArgument(rc));

    return rc;
}

std::pair<int, std::optional<std::string>> Manager::HookLoadFileExtended(const Plugin::LoadType type,
                                                                         const string& file, const string& resolved) {
    HookArgumentList args;

    if ( HavePluginForHook(META_HOOK_PRE) ) {
        args.emplace_back(type);
        args.emplace_back(file);
        args.emplace_back(resolved);
        MetaHookPre(HOOK_LOAD_FILE_EXT, args);
    }

    hook_list* l = hooks[HOOK_LOAD_FILE_EXT];

    std::pair<int, std::optional<std::string>> rc = {-1, std::nullopt};

    if ( l )
        for ( const auto& [_, p] : *l ) {
            rc = p->HookLoadFileExtended(type, file, resolved);

            if ( rc.first >= 0 )
                break;
        }

    if ( HavePluginForHook(META_HOOK_POST) )
        MetaHookPost(HOOK_LOAD_FILE_EXT, args, HookArgument(rc));

    return rc;
}

std::pair<bool, ValPtr> Manager::HookCallFunction(const Func* func, zeek::detail::Frame* parent, Args* vecargs) const {
    HookArgumentList args;
    ValPList vargs;

    if ( HavePluginForHook(META_HOOK_PRE) ) {
        vargs.resize(vecargs->size());

        for ( const auto& v : *vecargs )
            vargs.push_back(v.get());

        args.emplace_back(func);
        args.emplace_back(parent);
        args.emplace_back(&vargs);
        MetaHookPre(HOOK_CALL_FUNCTION, args);
    }

    hook_list* l = hooks[HOOK_CALL_FUNCTION];

    std::pair<bool, ValPtr> rval{false, nullptr};

    if ( l ) {
        for ( const auto& [_, p] : *l ) {
            rval = p->HookFunctionCall(func, parent, vecargs);

            if ( rval.first )
                break;
        }
    }

    if ( HavePluginForHook(META_HOOK_POST) )
        MetaHookPost(HOOK_CALL_FUNCTION, args, HookArgument(std::make_pair(rval.first, rval.second.get())));

    return rval;
}

bool Manager::HookQueueEvent(Event* event) const {
    HookArgumentList args;

    if ( HavePluginForHook(META_HOOK_PRE) ) {
        args.emplace_back(event);
        MetaHookPre(HOOK_QUEUE_EVENT, args);
    }

    hook_list* l = hooks[HOOK_QUEUE_EVENT];

    bool result = false;

    if ( l )
        for ( const auto& [_, p] : *l ) {
            if ( p->HookQueueEvent(event) ) {
                result = true;
                break;
            }
        }

    if ( HavePluginForHook(META_HOOK_POST) )
        MetaHookPost(HOOK_QUEUE_EVENT, args, HookArgument(result));

    return result;
}

void Manager::HookDrainEvents() const {
    HookArgumentList args;

    if ( HavePluginForHook(META_HOOK_PRE) )
        MetaHookPre(HOOK_DRAIN_EVENTS, args);

    hook_list* l = hooks[HOOK_DRAIN_EVENTS];

    if ( l )
        for ( const auto& [_, p] : *l ) {
            p->HookDrainEvents();
        }

    if ( HavePluginForHook(META_HOOK_POST) )
        MetaHookPost(HOOK_DRAIN_EVENTS, args, HookArgument());
}

void Manager::HookSetupAnalyzerTree(Connection* conn) const {
    HookArgumentList args;

    if ( HavePluginForHook(META_HOOK_PRE) ) {
        args.emplace_back(conn);
        MetaHookPre(HOOK_SETUP_ANALYZER_TREE, args);
    }

    hook_list* l = hooks[HOOK_SETUP_ANALYZER_TREE];

    if ( l ) {
        for ( const auto& [_, p] : *l ) {
            p->HookSetupAnalyzerTree(conn);
        }
    }

    if ( HavePluginForHook(META_HOOK_POST) ) {
        MetaHookPost(HOOK_SETUP_ANALYZER_TREE, args, HookArgument());
    }
}

void Manager::HookUpdateNetworkTime(double network_time) const {
    HookArgumentList args;

    if ( HavePluginForHook(META_HOOK_PRE) ) {
        args.emplace_back(network_time);
        MetaHookPre(HOOK_UPDATE_NETWORK_TIME, args);
    }

    hook_list* l = hooks[HOOK_UPDATE_NETWORK_TIME];

    if ( l )
        for ( const auto& [_, p] : *l ) {
            p->HookUpdateNetworkTime(network_time);
        }

    if ( HavePluginForHook(META_HOOK_POST) )
        MetaHookPost(HOOK_UPDATE_NETWORK_TIME, args, HookArgument());
}

void Manager::HookObjDtor(void* obj) const {
    HookArgumentList args;

    if ( HavePluginForHook(META_HOOK_PRE) ) {
        args.emplace_back(obj);
        MetaHookPre(HOOK_OBJ_DTOR, args);
    }

    hook_list* l = hooks[HOOK_OBJ_DTOR];

    if ( l )
        for ( const auto& [_, p] : *l ) {
            p->HookObjDtor(obj);
        }

    if ( HavePluginForHook(META_HOOK_POST) )
        MetaHookPost(HOOK_OBJ_DTOR, args, HookArgument());
}

void Manager::HookLogInit(const std::string& writer, const std::string& instantiating_filter, bool local, bool remote,
                          const logging::WriterBackend::WriterInfo& info, int num_fields,
                          const threading::Field* const* fields) const {
    HookArgumentList args;

    if ( HavePluginForHook(META_HOOK_PRE) ) {
        args.emplace_back(writer);
        args.emplace_back(instantiating_filter);
        args.emplace_back(local);
        args.emplace_back(remote);
        args.emplace_back(&info);
        args.emplace_back(num_fields);
        args.emplace_back(std::make_pair(num_fields, fields));
        MetaHookPre(HOOK_LOG_INIT, args);
    }

    hook_list* l = hooks[HOOK_LOG_INIT];

    if ( l )
        for ( const auto& [_, p] : *l ) {
            p->HookLogInit(writer, instantiating_filter, local, remote, info, num_fields, fields);
        }

    if ( HavePluginForHook(META_HOOK_POST) )
        MetaHookPost(HOOK_LOG_INIT, args, HookArgument());
}

bool Manager::HookLogWrite(const std::string& writer, const std::string& filter,
                           const logging::WriterBackend::WriterInfo& info, int num_fields,
                           const threading::Field* const* fields, threading::Value** vals) const {
    HookArgumentList args;

    if ( HavePluginForHook(META_HOOK_PRE) ) {
        args.emplace_back(writer);
        args.emplace_back(filter);
        args.emplace_back(&info);
        args.emplace_back(num_fields);
        args.emplace_back(std::make_pair(num_fields, fields));
        args.emplace_back(vals);
        MetaHookPre(HOOK_LOG_WRITE, args);
    }

    hook_list* l = hooks[HOOK_LOG_WRITE];

    bool result = true;

    if ( l )
        for ( const auto& [_, p] : *l ) {
            if ( ! p->HookLogWrite(writer, filter, info, num_fields, fields, vals) ) {
                result = false;
                break;
            }
        }

    if ( HavePluginForHook(META_HOOK_POST) )
        MetaHookPost(HOOK_LOG_WRITE, args, HookArgument(result));

    return result;
}

bool Manager::HookReporter(const std::string& prefix, const EventHandlerPtr event, const Connection* conn,
                           const ValPList* addl, bool location, const zeek::detail::Location* location1,
                           const zeek::detail::Location* location2, bool time, const std::string& message)

{
    HookArgumentList args;

    if ( HavePluginForHook(META_HOOK_PRE) ) {
        args.emplace_back(prefix);
        args.emplace_back(conn);
        args.emplace_back(addl);
        args.emplace_back(location1);
        args.emplace_back(location2);
        args.emplace_back(location);
        args.emplace_back(time);
        args.emplace_back(message);
        MetaHookPre(HOOK_REPORTER, args);
    }

    hook_list* l = hooks[HOOK_REPORTER];

    bool result = true;

    if ( l ) {
        for ( const auto& [_, p] : *l ) {
            if ( ! p->HookReporter(prefix, event, conn, addl, location, location1, location2, time, message) ) {
                result = false;
                break;
            }
        }
    }

    if ( HavePluginForHook(META_HOOK_POST) )
        MetaHookPost(HOOK_REPORTER, args, HookArgument(result));

    return result;
}

void Manager::HookUnprocessedPacket(const Packet* packet) const {
    HookArgumentList args;

    if ( HavePluginForHook(META_HOOK_PRE) ) {
        args.emplace_back(packet);
        MetaHookPre(HOOK_UNPROCESSED_PACKET, args);
    }

    hook_list* l = hooks[HOOK_UNPROCESSED_PACKET];

    if ( l )
        for ( const auto& [_, p] : *l ) {
            p->HookUnprocessedPacket(packet);
        }

    if ( HavePluginForHook(META_HOOK_POST) )
        MetaHookPost(HOOK_UNPROCESSED_PACKET, args, HookArgument());
}

bool Manager::HookPublishEvent(zeek::cluster::Backend& backend, const std::string& topic,
                               zeek::cluster::Event& event) const {
    HookArgumentList args;

    if ( HavePluginForHook(META_HOOK_PRE) ) {
        args.emplace_back(&backend);
        args.emplace_back(topic);
        args.emplace_back(&event);
        MetaHookPre(HOOK_PUBLISH_EVENT, args);
    }

    hook_list* l = hooks[HOOK_PUBLISH_EVENT];

    bool result = true;

    if ( l ) {
        for ( const auto& [_, p] : *l ) {
            if ( ! p->HookPublishEvent(backend, topic, event) ) {
                result = false;
                break;
            }
        }
    }

    if ( HavePluginForHook(META_HOOK_POST) )
        MetaHookPost(HOOK_PUBLISH_EVENT, args, HookArgument(result));

    return result;
}

void Manager::MetaHookPre(HookType hook, const HookArgumentList& args) const {
    if ( hook_list* l = hooks[META_HOOK_PRE] )
        for ( const auto& [hook_type, plugin] : *l )
            plugin->MetaHookPre(hook, args);
}

void Manager::MetaHookPost(HookType hook, const HookArgumentList& args, const HookArgument& result) const {
    if ( hook_list* l = hooks[META_HOOK_POST] )
        for ( const auto& [hook_type, plugin] : *l )
            plugin->MetaHookPost(hook, args, result);
}

} // namespace zeek::plugin
