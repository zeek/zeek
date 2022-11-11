// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Manager.h"

#include <dirent.h>
#include <dlfcn.h>
#include <glob.h>
#include <sys/stat.h>
#include <cerrno>
#include <climits> // for PATH_MAX
#include <cstdlib>
#include <fstream>
#include <optional>
#include <regex>
#include <sstream>

#include "zeek/Event.h"
#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/input.h"
#include "zeek/util.h"

using namespace std;

namespace zeek::plugin
	{

Plugin* Manager::current_plugin = nullptr;
const char* Manager::current_dir = nullptr;
const char* Manager::current_sopath = nullptr;

Manager::Manager()
	{
	init = false;
	hooks = new hook_list*[NUM_HOOKS];

	for ( int i = 0; i < NUM_HOOKS; i++ )
		hooks[i] = nullptr;
	}

Manager::~Manager()
	{
	assert(! init);

	for ( int i = 0; i < NUM_HOOKS; i++ )
		delete hooks[i];

	delete[] hooks;
	}

void Manager::SearchDynamicPlugins(const std::string& dir)
	{
	assert(! init);

	if ( dir.empty() )
		return;

	if ( dir.find(':') != string::npos )
		{
		// Split at ":".
		std::stringstream s(dir);
		std::string d;

		while ( std::getline(s, d, ':') )
			SearchDynamicPlugins(d);

		return;
		}

	if ( ! util::is_dir(dir) )
		{
		DBG_LOG(DBG_PLUGINS, "Not a valid plugin directory: %s", dir.c_str());
		return;
		}

	char canon_path[PATH_MAX];
	if ( ! realpath(dir.data(), canon_path) )
		{
		DBG_LOG(DBG_PLUGINS, "skip dynamic plugin search in %s, realpath failed: %s", dir.data(),
		        strerror(errno));
		return;
		}

	if ( searched_dirs.count(canon_path) )
		return;

	searched_dirs.emplace(canon_path);

	// Check if it's a plugin directory.

	const std::string magic = dir + "/__bro_plugin__";

	if ( util::is_file(magic) )
		{
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

		if ( dynamic_plugins.find(lower_name) != dynamic_plugins.end() )
			{
			DBG_LOG(DBG_PLUGINS, "Found already known plugin %s in %s, ignoring", name.c_str(),
			        dir.c_str());
			return;
			}

		// Record it, so that we can later activate it.
		dynamic_plugins.insert(std::make_pair(lower_name, dir));

		DBG_LOG(DBG_PLUGINS, "Found plugin %s in %s", name.c_str(), dir.c_str());
		return;
		}

	// No plugin here, traverse subdirectories.

	DIR* d = opendir(dir.c_str());

	if ( ! d )
		{
		DBG_LOG(DBG_PLUGINS, "Cannot open directory %s", dir.c_str());
		return;
		}

	bool found = false;

	struct dirent* dp;

	while ( (dp = readdir(d)) )
		{
		struct stat st;

		if ( strcmp(dp->d_name, "..") == 0 || strcmp(dp->d_name, ".") == 0 )
			continue;

		string path = dir + "/" + dp->d_name;

		if ( stat(path.c_str(), &st) < 0 )
			{
			DBG_LOG(DBG_PLUGINS, "Cannot stat %s: %s", path.c_str(), strerror(errno));
			continue;
			}

		if ( st.st_mode & S_IFDIR )
			SearchDynamicPlugins(path);
		}

	closedir(d);
	}

bool Manager::ActivateDynamicPluginInternal(const std::string& name, bool ok_if_not_found,
                                            std::vector<std::string>* errors)
	{
	errors->clear(); // caller should pass it in empty, but just to be sure

	dynamic_plugin_map::iterator m = dynamic_plugins.find(util::strtolower(name));

	plugin_list* all_plugins = Manager::ActivePluginsInternal();

	if ( m == dynamic_plugins.end() )
		{
		if ( ok_if_not_found )
			return true;

		// Check if it's a static built-in plugin; they are always
		// active, so just ignore. Not the most efficient way, but
		// this should be rare to begin with.
		for ( const auto& p : *all_plugins )
			{
			if ( p->Name() == name )
				return true;
			}

		errors->push_back(util::fmt("plugin %s is not available", name.c_str()));
		return false;
		}

	if ( m->second.empty() )
		{
		// That's our marker that we have already activated this
		// plugin. Silently ignore the new request.
		return true;
		}

	std::string dir = m->second + "/";

	DBG_LOG(DBG_PLUGINS, "Activating plugin %s", name.c_str());

	// If there's a plugin with the same name already, report an error and let
	// the user do the conflict resolution.
	auto lower_name = util::strtolower(name);
	for ( const auto& p : *all_plugins )
		{
		if ( util::strtolower(p->Name()) == lower_name )
			{
			auto v = p->Version();
			auto error = util::fmt(
				"dynamic plugin %s from directory %s conflicts with %s plugin %s (%d.%d.%d)",
				name.c_str(), dir.c_str(), p->DynamicPlugin() ? "dynamic" : "built-in",
				p->Name().c_str(), v.major, v.minor, v.patch);
			errors->push_back(error);
			return false;
			}
		}

	// Load shared libraries.

	string dypattern = dir + "/lib/*." + HOST_ARCHITECTURE + DYNAMIC_PLUGIN_SUFFIX;

	DBG_LOG(DBG_PLUGINS, "  Searching for shared libraries %s", dypattern.c_str());

	glob_t gl;

	if ( glob(dypattern.c_str(), 0, 0, &gl) == 0 )
		{
		for ( size_t i = 0; i < gl.gl_pathc; i++ )
			{
			const char* path = gl.gl_pathv[i];

			current_plugin = nullptr;
			current_dir = dir.c_str();
			current_sopath = path;
			void* hdl = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
			current_dir = nullptr;
			current_sopath = nullptr;

			if ( ! hdl )
				{
				const char* err = dlerror();
				errors->push_back(util::fmt("cannot load plugin library %s: %s", path,
				                            err ? err : "<unknown error>"));
				continue;
				}

			if ( ! current_plugin )
				{
				errors->push_back(
					util::fmt("load plugin library %s did not instantiate a plugin", path));
				continue;
				}

			current_plugin->SetDynamic(true);
			current_plugin->DoConfigure();
			DBG_LOG(DBG_PLUGINS, "  InitializingComponents");
			current_plugin->InitializeComponents();

			plugins_by_path.insert(
				std::make_pair(util::detail::normalize_path(dir), current_plugin));

			// We execute the pre-script initialization here; this in
			// fact could be *during* script initialization if we got
			// triggered via @load-plugin.
			current_plugin->InitPreScript();

			// Make sure the name the plugin reports is consistent with
			// what we expect from its magic file.
			if ( util::strtolower(current_plugin->Name()) != util::strtolower(name) )
				{
				errors->push_back(util::fmt("inconsistent plugin name: %s vs %s",
				                            current_plugin->Name().c_str(), name.c_str()));
				continue;
				}

			current_plugin = nullptr;
			DBG_LOG(DBG_PLUGINS, "  Loaded %s", path);
			}

		globfree(&gl);

		if ( ! errors->empty() )
			return false;
		}

	else
		{
		DBG_LOG(DBG_PLUGINS, "  No shared library found");
		}

	// Add the "scripts" and "bif" directories to ZEEKPATH.
	std::string scripts = dir + "scripts";

	if ( util::is_dir(scripts) )
		{
		DBG_LOG(DBG_PLUGINS, "  Adding %s to ZEEKPATH", scripts.c_str());
		util::detail::add_to_zeek_path(scripts);
		}

	string init;

	// First load {scripts}/__preload__.zeek automatically.
	init = dir + "scripts/__preload__.zeek";

	if ( util::is_file(init) )
		{
		DBG_LOG(DBG_PLUGINS, "  Loading %s", init.c_str());
		scripts_to_load.push_back(init);
		}

	// Load {bif,scripts}/__load__.zeek automatically.
	init = dir + "lib/bif/__load__.zeek";

	if ( util::is_file(init) )
		{
		DBG_LOG(DBG_PLUGINS, "  Loading %s", init.c_str());
		scripts_to_load.push_back(init);
		}

	init = dir + "scripts/__load__.zeek";

	if ( util::is_file(init) )
		{
		DBG_LOG(DBG_PLUGINS, "  Loading %s", init.c_str());
		scripts_to_load.push_back(init);
		}

	// Mark this plugin as activated by clearing the path.
	m->second.clear();

	return true;
	}

void Manager::ActivateDynamicPlugin(const std::string& name)
	{
	std::vector<std::string> errors;
	if ( ActivateDynamicPluginInternal(name, false, &errors) )
		UpdateInputFiles();
	else
		// Reschedule for another attempt later.
		requested_plugins.insert(std::move(name));
	}

void Manager::ActivateDynamicPlugins(bool all)
	{
	// Tracks plugins we need to activate as pairs of their names and booleans
	// indicating whether an activation failure is to be deemed a fatal error.
	std::set<std::pair<std::string, bool>> plugins_to_activate;

	// Activate plugins that were specifically requested.
	for ( const auto& x : requested_plugins )
		plugins_to_activate.emplace(x, false);

	// Activate plugins that our environment tells us to.
	vector<string> p;
	util::tokenize_string(util::zeek_plugin_activate(), ",", &p);

	for ( const auto& x : p )
		plugins_to_activate.emplace(x, true);

	if ( all )
		{
		// Activate all other ones we discovered.
		for ( const auto& x : dynamic_plugins )
			plugins_to_activate.emplace(x.first, false);
		}

	// Now we keep iterating over all the plugins, trying to load them, for as
	// long as we're successful for at least one further of them each round.
	// Doing so ensures that we can resolve (non-cyclic) load dependencies
	// independent of any particular order.
	while ( ! plugins_to_activate.empty() )
		{
		std::vector<std::string> errors;
		auto plugins_left = plugins_to_activate;

		for ( const auto& x : plugins_to_activate )
			{
			if ( ActivateDynamicPluginInternal(x.first, x.second, &errors) )
				plugins_left.erase(x);
			}

		if ( plugins_left.size() == plugins_to_activate.size() )
			{
			// Could not load a single further plugin this round, that's fatal.
			for ( const auto& msg : errors )
				reporter->Error("%s", msg.c_str());

			reporter->FatalError("aborting after plugin errors");
			}

		plugins_to_activate = std::move(plugins_left);
		}

	UpdateInputFiles();
	}

void Manager::UpdateInputFiles()
	{
	for ( file_list::const_reverse_iterator i = scripts_to_load.rbegin();
	      i != scripts_to_load.rend(); i++ )
		add_input_file_at_front((*i).c_str());

	scripts_to_load.clear();
	}

static bool plugin_cmp(const Plugin* a, const Plugin* b)
	{
	return util::strtolower(a->Name()) < util::strtolower(b->Name());
	}

void Manager::RegisterPlugin(Plugin* plugin)
	{
	Manager::ActivePluginsInternal()->push_back(plugin);

	if ( current_dir && current_sopath )
		// A dynamic plugin, record its location.
		plugin->SetPluginLocation(util::detail::normalize_path(current_dir), current_sopath);

	current_plugin = plugin;
	}

void Manager::RegisterBifFile(const char* plugin, bif_init_func c)
	{
	bif_init_func_map* bifs = BifFilesInternal();

	std::string lower_plugin = util::strtolower(plugin);
	bif_init_func_map::iterator i = bifs->find(lower_plugin);

	if ( i == bifs->end() )
		i = bifs->insert(std::make_pair(lower_plugin, new bif_init_func_list())).first;

	i->second->push_back(c);
	}

void Manager::ExtendZeekPathForPlugins()
	{
	// Extend the path outside of the loop to avoid looking through a longer path for each plugin
	vector<string> path_additions;

	for ( const auto& p : Manager::ActivePlugins() )
		{
		if ( p->DynamicPlugin() || p->Name().empty() )
			continue;

		try
			{
			string canon = std::regex_replace(p->Name(), std::regex("::"), "_");
			string dir = "builtin-plugins/" + canon;

			// Use find_file to find the directory in the path.
			string script_dir = util::find_file(dir, util::zeek_path());
			if ( script_dir.empty() || ! util::is_dir(script_dir) )
				continue;

			DBG_LOG(DBG_PLUGINS, "  Adding %s to ZEEKPATH", script_dir.c_str());
			path_additions.push_back(script_dir);
			}
		catch ( const std::regex_error& e )
			{
			// This really shouldn't ever happen, but we do need to catch the exception.
			// Report a fatal error because something is wrong if this occurs.
			reporter->FatalError("Failed to replace colons in plugin name %s: %s",
			                     p->Name().c_str(), e.what());
			}
		}

	for ( const auto& plugin_path : path_additions )
		util::detail::add_to_zeek_path(plugin_path);
	}

void Manager::InitPreScript()
	{
	assert(! init);

	for ( plugin_list::iterator i = Manager::ActivePluginsInternal()->begin();
	      i != Manager::ActivePluginsInternal()->end(); i++ )
		{
		(*i)->DoConfigure();
		}

	// Sort plugins by name to make sure we have a deterministic order.
	// We cannot do this before, because the plugin name (used for plugin_cmp) is only
	// set in DoConfigure.
	// We need things sorted to generate the tags (in InitializeComponents) in a deterministic
	// order.
	ActivePluginsInternal()->sort(plugin_cmp);

	for ( plugin_list::iterator i = Manager::ActivePluginsInternal()->begin();
	      i != Manager::ActivePluginsInternal()->end(); i++ )
		{
		(*i)->InitializeComponents();
		(*i)->InitPreScript();
		}

	init = true;
	}

void Manager::InitBifs()
	{
	bif_init_func_map* bifs = BifFilesInternal();

	for ( plugin_list::iterator i = Manager::ActivePluginsInternal()->begin();
	      i != Manager::ActivePluginsInternal()->end(); i++ )
		{
		bif_init_func_map::const_iterator b = bifs->find(util::strtolower((*i)->Name()));

		if ( b != bifs->end() )
			{
			for ( bif_init_func_list::const_iterator j = b->second->begin(); j != b->second->end();
			      ++j )
				(**j)(*i);
			}
		}
	}

void Manager::InitPostScript()
	{
	assert(init);

	for ( plugin_list::iterator i = Manager::ActivePluginsInternal()->begin();
	      i != Manager::ActivePluginsInternal()->end(); i++ )
		(*i)->InitPostScript();
	}

void Manager::FinishPlugins()
	{
	assert(init);

	for ( plugin_list::iterator i = Manager::ActivePluginsInternal()->begin();
	      i != Manager::ActivePluginsInternal()->end(); i++ )
		(*i)->Done();

	Manager::ActivePluginsInternal()->clear();

	init = false;
	}

Manager::plugin_list Manager::ActivePlugins() const
	{
	return *Manager::ActivePluginsInternal();
	}

Manager::inactive_plugin_list Manager::InactivePlugins() const
	{
	plugin_list* all = ActivePluginsInternal();

	inactive_plugin_list inactives;

	for ( dynamic_plugin_map::const_iterator i = dynamic_plugins.begin();
	      i != dynamic_plugins.end(); i++ )
		{
		bool found = false;

		for ( plugin_list::const_iterator j = all->begin(); j != all->end(); j++ )
			{
			if ( (*i).first == util::strtolower((*j)->Name()) )
				{
				found = true;
				break;
				}
			}

		if ( ! found )
			inactives.push_back(*i);
		}

	return inactives;
	}

Manager::plugin_list* Manager::ActivePluginsInternal()
	{
	static plugin_list* plugins = nullptr;

	if ( ! plugins )
		plugins = new plugin_list;

	return plugins;
	}

Manager::bif_init_func_map* Manager::BifFilesInternal()
	{
	static bif_init_func_map* bifs = nullptr;

	if ( ! bifs )
		bifs = new bif_init_func_map;

	return bifs;
	}

Plugin* Manager::LookupPluginByPath(std::string_view _path)
	{
	auto path = util::detail::normalize_path(_path);

	if ( util::is_file(path) )
		path = util::SafeDirname(path).result;

	while ( path.size() )
		{
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

static bool hook_cmp(std::pair<int, Plugin*> a, std::pair<int, Plugin*> b)
	{
	if ( a.first == b.first )
		return util::strtolower(a.second->Name()) < util::strtolower(a.second->Name());

	// Reverse sort.
	return a.first > b.first;
	}

std::list<std::pair<HookType, int>> Manager::HooksEnabledForPlugin(const Plugin* plugin) const
	{
	std::list<std::pair<HookType, int>> enabled;

	for ( int i = 0; i < NUM_HOOKS; i++ )
		{
		if ( hook_list* l = hooks[i] )
			for ( const auto& [hook, hook_plugin] : *l )
				if ( hook_plugin == plugin )
					enabled.push_back(std::make_pair(static_cast<HookType>(i), hook));
		}

	return enabled;
	}

void Manager::EnableHook(HookType hook, Plugin* plugin, int prio)
	{
	if ( ! hooks[hook] )
		hooks[hook] = new hook_list;

	hook_list* l = hooks[hook];

	for ( hook_list::iterator i = l->begin(); i != l->end(); i++ )
		{
		// Already enabled for this plugin.
		if ( (*i).second == plugin )
			return;
		}

	l->push_back(std::make_pair(prio, plugin));
	l->sort(hook_cmp);
	}

void Manager::DisableHook(HookType hook, Plugin* plugin)
	{
	hook_list* l = hooks[hook];

	if ( ! l )
		return;

	for ( hook_list::iterator i = l->begin(); i != l->end(); i++ )
		{
		if ( (*i).second == plugin )
			{
			l->erase(i);
			break;
			}
		}

	if ( l->empty() )
		{
		delete l;
		hooks[hook] = nullptr;
		}
	}

void Manager::RequestEvent(EventHandlerPtr handler, Plugin* plugin)
	{
	DBG_LOG(DBG_PLUGINS, "Plugin %s requested event %s", plugin->Name().c_str(), handler->Name());
	handler->SetGenerateAlways();
	}

void Manager::RequestBroObjDtor(Obj* obj, Plugin* plugin)
	{
	obj->NotifyPluginsOnDtor();
	}

void Manager::RequestObjDtor(Obj* obj, Plugin* plugin)
	{
	obj->NotifyPluginsOnDtor();
	}

int Manager::HookLoadFile(const Plugin::LoadType type, const string& file, const string& resolved)
	{
	HookArgumentList args;

	if ( HavePluginForHook(META_HOOK_PRE) )
		{
		args.push_back(HookArgument(type));
		args.push_back(HookArgument(file));
		args.push_back(HookArgument(resolved));
		MetaHookPre(HOOK_LOAD_FILE, args);
		}

	hook_list* l = hooks[HOOK_LOAD_FILE];

	int rc = -1;

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;

			rc = p->HookLoadFile(type, file, resolved);

			if ( rc >= 0 )
				break;
			}

	if ( HavePluginForHook(META_HOOK_POST) )
		MetaHookPost(HOOK_LOAD_FILE, args, HookArgument(rc));

	return rc;
	}

std::pair<int, std::optional<std::string>>
Manager::HookLoadFileExtended(const Plugin::LoadType type, const string& file,
                              const string& resolved)
	{
	HookArgumentList args;

	if ( HavePluginForHook(META_HOOK_PRE) )
		{
		args.push_back(HookArgument(type));
		args.push_back(HookArgument(file));
		args.push_back(HookArgument(resolved));
		MetaHookPre(HOOK_LOAD_FILE_EXT, args);
		}

	hook_list* l = hooks[HOOK_LOAD_FILE_EXT];

	std::pair<int, std::optional<std::string>> rc = {-1, std::nullopt};

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;

			rc = p->HookLoadFileExtended(type, file, resolved);

			if ( rc.first >= 0 )
				break;
			}

	if ( HavePluginForHook(META_HOOK_POST) )
		MetaHookPost(HOOK_LOAD_FILE_EXT, args, HookArgument(rc));

	return rc;
	}

std::pair<bool, ValPtr> Manager::HookCallFunction(const Func* func, zeek::detail::Frame* parent,
                                                  Args* vecargs) const
	{
	HookArgumentList args;
	ValPList vargs;

	if ( HavePluginForHook(META_HOOK_PRE) )
		{
		vargs.resize(vecargs->size());

		for ( const auto& v : *vecargs )
			vargs.push_back(v.get());

		args.push_back(HookArgument(func));
		args.push_back(HookArgument(parent));
		args.push_back(HookArgument(&vargs));
		MetaHookPre(HOOK_CALL_FUNCTION, args);
		}

	hook_list* l = hooks[HOOK_CALL_FUNCTION];

	std::pair<bool, ValPtr> rval{false, nullptr};

	if ( l )
		{
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;

			rval = p->HookFunctionCall(func, parent, vecargs);

			if ( rval.first )
				break;
			}
		}

	if ( HavePluginForHook(META_HOOK_POST) )
		MetaHookPost(HOOK_CALL_FUNCTION, args,
		             HookArgument(std::make_pair(rval.first, rval.second.get())));

	return rval;
	}

bool Manager::HookQueueEvent(Event* event) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(META_HOOK_PRE) )
		{
		args.push_back(HookArgument(event));
		MetaHookPre(HOOK_QUEUE_EVENT, args);
		}

	hook_list* l = hooks[HOOK_QUEUE_EVENT];

	bool result = false;

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;

			if ( p->HookQueueEvent(event) )
				{
				result = true;
				break;
				}
			}

	if ( HavePluginForHook(META_HOOK_POST) )
		MetaHookPost(HOOK_QUEUE_EVENT, args, HookArgument(result));

	return result;
	}

void Manager::HookDrainEvents() const
	{
	HookArgumentList args;

	if ( HavePluginForHook(META_HOOK_PRE) )
		MetaHookPre(HOOK_DRAIN_EVENTS, args);

	hook_list* l = hooks[HOOK_DRAIN_EVENTS];

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;
			p->HookDrainEvents();
			}

	if ( HavePluginForHook(META_HOOK_POST) )
		MetaHookPost(HOOK_DRAIN_EVENTS, args, HookArgument());
	}

void Manager::HookSetupAnalyzerTree(Connection* conn) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(META_HOOK_PRE) )
		{
		args.push_back(HookArgument(conn));
		MetaHookPre(HOOK_SETUP_ANALYZER_TREE, args);
		}

	hook_list* l = hooks[HOOK_SETUP_ANALYZER_TREE];

	if ( l )
		{
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;
			p->HookSetupAnalyzerTree(conn);
			}
		}

	if ( HavePluginForHook(META_HOOK_POST) )
		{
		MetaHookPost(HOOK_SETUP_ANALYZER_TREE, args, HookArgument());
		}
	}

void Manager::HookUpdateNetworkTime(double network_time) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(META_HOOK_PRE) )
		{
		args.push_back(HookArgument(network_time));
		MetaHookPre(HOOK_UPDATE_NETWORK_TIME, args);
		}

	hook_list* l = hooks[HOOK_UPDATE_NETWORK_TIME];

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;
			p->HookUpdateNetworkTime(network_time);
			}

	if ( HavePluginForHook(META_HOOK_POST) )
		MetaHookPost(HOOK_UPDATE_NETWORK_TIME, args, HookArgument());
	}

void Manager::HookBroObjDtor(void* obj) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(META_HOOK_PRE) )
		{
		args.push_back(HookArgument(obj));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
		MetaHookPre(HOOK_BRO_OBJ_DTOR, args);
#pragma GCC diagnostic pop
		}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	hook_list* l = hooks[HOOK_BRO_OBJ_DTOR];
#pragma GCC diagnostic pop

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
			p->HookBroObjDtor(obj);
#pragma GCC diagnostic pop
			}

	if ( HavePluginForHook(META_HOOK_POST) )
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
		MetaHookPost(HOOK_BRO_OBJ_DTOR, args, HookArgument());
#pragma GCC diagnostic pop
	}

void Manager::HookObjDtor(void* obj) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(META_HOOK_PRE) )
		{
		args.push_back(HookArgument(obj));
		MetaHookPre(HOOK_OBJ_DTOR, args);
		}

	hook_list* l = hooks[HOOK_OBJ_DTOR];

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;
			p->HookObjDtor(obj);
			}

	if ( HavePluginForHook(META_HOOK_POST) )
		MetaHookPost(HOOK_OBJ_DTOR, args, HookArgument());
	}

void Manager::HookLogInit(const std::string& writer, const std::string& instantiating_filter,
                          bool local, bool remote, const logging::WriterBackend::WriterInfo& info,
                          int num_fields, const threading::Field* const* fields) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(META_HOOK_PRE) )
		{
		args.push_back(HookArgument(writer));
		args.push_back(HookArgument(instantiating_filter));
		args.push_back(HookArgument(local));
		args.push_back(HookArgument(remote));
		args.push_back(HookArgument(&info));
		args.push_back(HookArgument(num_fields));
		args.push_back(HookArgument(std::make_pair(num_fields, fields)));
		MetaHookPre(HOOK_LOG_INIT, args);
		}

	hook_list* l = hooks[HOOK_LOG_INIT];

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;
			p->HookLogInit(writer, instantiating_filter, local, remote, info, num_fields, fields);
			}

	if ( HavePluginForHook(META_HOOK_POST) )
		MetaHookPost(HOOK_LOG_INIT, args, HookArgument());
	}

bool Manager::HookLogWrite(const std::string& writer, const std::string& filter,
                           const logging::WriterBackend::WriterInfo& info, int num_fields,
                           const threading::Field* const* fields, threading::Value** vals) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(META_HOOK_PRE) )
		{
		args.push_back(HookArgument(writer));
		args.push_back(HookArgument(filter));
		args.push_back(HookArgument(&info));
		args.push_back(HookArgument(num_fields));
		args.push_back(HookArgument(std::make_pair(num_fields, fields)));
		args.push_back(HookArgument(vals));
		MetaHookPre(HOOK_LOG_WRITE, args);
		}

	hook_list* l = hooks[HOOK_LOG_WRITE];

	bool result = true;

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;

			if ( ! p->HookLogWrite(writer, filter, info, num_fields, fields, vals) )
				{
				result = false;
				break;
				}
			}

	if ( HavePluginForHook(META_HOOK_POST) )
		MetaHookPost(HOOK_LOG_WRITE, args, HookArgument(result));

	return result;
	}

bool Manager::HookReporter(const std::string& prefix, const EventHandlerPtr event,
                           const Connection* conn, const ValPList* addl, bool location,
                           const zeek::detail::Location* location1,
                           const zeek::detail::Location* location2, bool time,
                           const std::string& message)

	{
	HookArgumentList args;

	if ( HavePluginForHook(META_HOOK_PRE) )
		{
		args.push_back(HookArgument(prefix));
		args.push_back(HookArgument(conn));
		args.push_back(HookArgument(addl));
		args.push_back(HookArgument(location1));
		args.push_back(HookArgument(location2));
		args.push_back(HookArgument(location));
		args.push_back(HookArgument(time));
		args.push_back(HookArgument(message));
		MetaHookPre(HOOK_REPORTER, args);
		}

	hook_list* l = hooks[HOOK_REPORTER];

	bool result = true;

	if ( l )
		{
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;

			if ( ! p->HookReporter(prefix, event, conn, addl, location, location1, location2, time,
			                       message) )
				{
				result = false;
				break;
				}
			}
		}

	if ( HavePluginForHook(META_HOOK_POST) )
		MetaHookPost(HOOK_REPORTER, args, HookArgument(result));

	return result;
	}

void Manager::HookUnprocessedPacket(const Packet* packet) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(META_HOOK_PRE) )
		{
		args.emplace_back(HookArgument{packet});
		MetaHookPre(HOOK_UNPROCESSED_PACKET, args);
		}

	hook_list* l = hooks[HOOK_UNPROCESSED_PACKET];

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;
			p->HookUnprocessedPacket(packet);
			}

	if ( HavePluginForHook(META_HOOK_POST) )
		MetaHookPost(HOOK_UNPROCESSED_PACKET, args, HookArgument());
	}

void Manager::MetaHookPre(HookType hook, const HookArgumentList& args) const
	{
	if ( hook_list* l = hooks[HOOK_CALL_FUNCTION] )
		for ( const auto& [hook_type, plugin] : *l )
			plugin->MetaHookPre(hook, args);
	}

void Manager::MetaHookPost(HookType hook, const HookArgumentList& args,
                           const HookArgument& result) const
	{
	if ( hook_list* l = hooks[HOOK_CALL_FUNCTION] )
		for ( const auto& [hook_type, plugin] : *l )
			plugin->MetaHookPost(hook, args, result);
	}

	} // namespace zeek::plugin
