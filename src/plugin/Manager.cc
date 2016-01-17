// See the file "COPYING" in the main distribution directory for copyright.

#include <sstream>
#include <fstream>
#include <dirent.h>
#include <glob.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/stat.h>

#include "Manager.h"

#include "../Reporter.h"
#include "../Func.h"
#include "../Event.h"

using namespace plugin;

Plugin* Manager::current_plugin = 0;
const char* Manager::current_dir = 0;
const char* Manager::current_sopath = 0;

Manager::Manager()
	{
	init = false;
	hooks = new hook_list*[NUM_HOOKS];

	for ( int i = 0; i < NUM_HOOKS; i++ )
		hooks[i] = 0;
	}

Manager::~Manager()
	{
	assert(! init);

	for ( int i = 0; i < NUM_HOOKS; i++ )
		delete hooks[i];

	delete [] hooks;
	}

void Manager::SearchDynamicPlugins(const std::string& dir)
	{
	assert(! init);

	if ( dir.empty() )
		return;

	if ( dir.find(":") != string::npos )
		{
		// Split at ":".
		std::stringstream s(dir);
		std::string d;

		while ( std::getline(s, d, ':') )
			SearchDynamicPlugins(d);

		return;
		}

	if ( ! is_dir(dir) )
		{
		DBG_LOG(DBG_PLUGINS, "Not a valid plugin directory: %s", dir.c_str());
		return;
		}

	// Check if it's a plugin dirctory.

	const std::string magic = dir + "/__bro_plugin__";

	if ( is_file(magic) )
		{
		// It's a plugin, get it's name.
		std::ifstream in(magic.c_str());

		if ( in.fail() )
			reporter->FatalError("cannot open plugin magic file %s", magic.c_str());

		std::string name;
		std::getline(in, name);
		strstrip(name);
		string lower_name = strtolower(name);

		if ( name.empty() )
			reporter->FatalError("empty plugin magic file %s", magic.c_str());

		if ( dynamic_plugins.find(lower_name) != dynamic_plugins.end() )
			{
			DBG_LOG(DBG_PLUGINS, "Found already known plugin %s in %s, ignoring", name.c_str(), dir.c_str());
			return;
			}

		// Record it, so that we can later activate it.
		dynamic_plugins.insert(std::make_pair(lower_name, dir));

		DBG_LOG(DBG_PLUGINS, "Found plugin %s in %s", name.c_str(), dir.c_str());
		return;
		}

	// No plugin here, traverse subirectories.

	DIR* d = opendir(dir.c_str());

	if ( ! d )
		{
		DBG_LOG(DBG_PLUGINS, "Cannot open directory %s", dir.c_str());
		return;
		}

	bool found = false;

	struct dirent *dp;

	while ( (dp = readdir(d)) )
		{
		struct stat st;

		if ( strcmp(dp->d_name, "..") == 0
		     || strcmp(dp->d_name, ".") == 0 )
			continue;

		string path = dir + "/" + dp->d_name;

		if( stat(path.c_str(), &st) < 0 )
			{
			DBG_LOG(DBG_PLUGINS, "Cannot stat %s: %s", path.c_str(), strerror(errno));
			continue;
			}

		if ( st.st_mode & S_IFDIR )
			SearchDynamicPlugins(path);
		}

	closedir(d);
	}

bool Manager::ActivateDynamicPluginInternal(const std::string& name, bool ok_if_not_found)
	{
	dynamic_plugin_map::iterator m = dynamic_plugins.find(strtolower(name));

	if ( m == dynamic_plugins.end() )
		{
		if ( ok_if_not_found )
			return true;

		// Check if it's a static built-in plugin; they are always
		// active, so just ignore. Not the most efficient way, but
		// this should be rare to begin with.
		plugin_list* all_plugins = Manager::ActivePluginsInternal();

		for ( plugin::Manager::plugin_list::const_iterator i = all_plugins->begin(); i != all_plugins->end(); i++ )
			{
			if ( (*i)->Name() == name )
				return true;
			}

		reporter->Error("plugin %s is not available", name.c_str());
		return false;
		}

	if ( m->second == "" )
		// Already activated.
		return true;

	std::string dir = m->second + "/";

	if ( dir.empty() )
		{
		// That's our marker that we have already activated this
		// plugin. Silently ignore the new request.
		return true;
		}

	DBG_LOG(DBG_PLUGINS, "Activating plugin %s", name.c_str());

	// Add the "scripts" and "bif" directories to BROPATH.
	std::string scripts = dir + "scripts";

	if ( is_dir(scripts) )
		{
		DBG_LOG(DBG_PLUGINS, "  Adding %s to BROPATH", scripts.c_str());
		add_to_bro_path(scripts);
		}

	// First load {scripts}/__preload__.bro automatically.
	string init = dir + "scripts/__preload__.bro";

	if ( is_file(init) )
		{
		DBG_LOG(DBG_PLUGINS, "  Loading %s", init.c_str());
		scripts_to_load.push_back(init);
		}

	// Load {bif,scripts}/__load__.bro automatically.
	init = dir + "lib/bif/__load__.bro";

	if ( is_file(init) )
		{
		DBG_LOG(DBG_PLUGINS, "  Loading %s", init.c_str());
		scripts_to_load.push_back(init);
		}

	init = dir + "scripts/__load__.bro";

	if ( is_file(init) )
		{
		DBG_LOG(DBG_PLUGINS, "  Loading %s", init.c_str());
		scripts_to_load.push_back(init);
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

			current_plugin = 0;
			current_dir = dir.c_str();
			current_sopath = path;
			void* hdl = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);

			if ( ! hdl )
				{
				const char* err = dlerror();
				reporter->FatalError("cannot load plugin library %s: %s", path, err ? err : "<unknown error>");
				}

			if ( ! current_plugin )
				reporter->FatalError("load plugin library %s did not instantiate a plugin", path);

			current_plugin->SetDynamic(true);
			current_plugin->DoConfigure();

			if ( current_plugin->APIVersion() != BRO_PLUGIN_API_VERSION )
				reporter->FatalError("plugin's API version does not match Bro (expected %d, got %d in %s)",
						     BRO_PLUGIN_API_VERSION, current_plugin->APIVersion(), path);

			// We execute the pre-script initialization here; this in
			// fact could be *during* script initialization if we got
			// triggered via @load-plugin.
			current_plugin->InitPreScript();

			// Make sure the name the plugin reports is consistent with
			// what we expect from its magic file.
			if ( strtolower(current_plugin->Name()) != strtolower(name) )
				reporter->FatalError("inconsistent plugin name: %s vs %s",
						     current_plugin->Name().c_str(), name.c_str());

			current_dir = 0;
			current_sopath = 0;
			current_plugin = 0;

			DBG_LOG(DBG_PLUGINS, "  Loaded %s", path);
			}
		}

	else
		{
		DBG_LOG(DBG_PLUGINS, "  No shared library found");
		}

	// Mark this plugin as activated by clearing the path.
	m->second.clear();

	return true;
	}

bool Manager::ActivateDynamicPlugin(const std::string& name)
	{
	if ( ! ActivateDynamicPluginInternal(name) )
		return false;

	UpdateInputFiles();
	return true;
	}

bool Manager::ActivateDynamicPlugins(bool all)
	{
	// Activate plugins that our environment tells us to.
	vector<string> p;
	tokenize_string(bro_plugin_activate(), ",", &p);

	for ( size_t n = 0; n < p.size(); ++n )
		ActivateDynamicPluginInternal(p[n], true);

	if ( all )
		{
		for ( dynamic_plugin_map::const_iterator i = dynamic_plugins.begin();
		      i != dynamic_plugins.end(); i++ )
			{
			if ( ! ActivateDynamicPluginInternal(i->first) )
				return false;
			}
		}

	UpdateInputFiles();

	return true;
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
	return strtolower(a->Name()) < strtolower(b->Name());
	}

void Manager::RegisterPlugin(Plugin *plugin)
	{
	Manager::ActivePluginsInternal()->push_back(plugin);

	if ( current_dir && current_sopath )
		// A dynamic plugin, record its location.
		plugin->SetPluginLocation(current_dir, current_sopath);

	// Sort plugins by name to make sure we have a deterministic order.
	ActivePluginsInternal()->sort(plugin_cmp);

	current_plugin = plugin;
	}

void Manager::RegisterBifFile(const char* plugin, bif_init_func c)
	{
	bif_init_func_map* bifs = BifFilesInternal();

	std::string lower_plugin = strtolower(plugin);
	bif_init_func_map::iterator i = bifs->find(lower_plugin);

	if ( i == bifs->end() )
		i = bifs->insert(std::make_pair(lower_plugin, new bif_init_func_list())).first;

	i->second->push_back(c);
	}

void Manager::InitPreScript()
	{
	assert(! init);

	for ( plugin_list::iterator i = Manager::ActivePluginsInternal()->begin();
	      i != Manager::ActivePluginsInternal()->end(); i++ )
		{
		Plugin* plugin = *i;
		plugin->DoConfigure();
		plugin->InitPreScript();
		}

	init = true;
	}

void Manager::InitBifs()
	{
	bif_init_func_map* bifs = BifFilesInternal();

	for ( plugin_list::iterator i = Manager::ActivePluginsInternal()->begin();
	      i != Manager::ActivePluginsInternal()->end(); i++ )
		{
		bif_init_func_map::const_iterator b = bifs->find(strtolower((*i)->Name()));

		if ( b != bifs->end() )
			{
			for ( bif_init_func_list::const_iterator j = b->second->begin(); j != b->second->end(); ++j )
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

	for ( dynamic_plugin_map::const_iterator i = dynamic_plugins.begin(); i != dynamic_plugins.end(); i++ )
		{
		bool found = false;

		for ( plugin_list::const_iterator j = all->begin(); j != all->end(); j++ )
			{
			if ( (*i).first == strtolower((*j)->Name()) )
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
	static plugin_list* plugins = 0;

	if ( ! plugins )
		plugins = new plugin_list;

	return plugins;
	}

Manager::bif_init_func_map* Manager::BifFilesInternal()
	{
	static bif_init_func_map* bifs = 0;

	if ( ! bifs )
		bifs = new bif_init_func_map;

	return bifs;
	}

static bool hook_cmp(std::pair<int, Plugin*> a, std::pair<int, Plugin*> b)
	{
	if ( a.first == b.first )
		return strtolower(a.second->Name()) < strtolower(a.second->Name());

	// Reverse sort.
	return a.first > b.first;
	}

std::list<std::pair<HookType, int> > Manager::HooksEnabledForPlugin(const Plugin* plugin) const
	{
	std::list<std::pair<HookType, int> > enabled;

	for ( int i = 0; i < NUM_HOOKS; i++ )
		{
		hook_list* l = hooks[i];

		if ( ! l )
			continue;

		for ( hook_list::iterator j = l->begin(); j != l->end(); j++ )
			{
			if ( (*j).second == plugin )
				enabled.push_back(std::make_pair((HookType)i, (*j).first));
			}
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
		hooks[hook] = 0;
		}
	}

void Manager::RequestEvent(EventHandlerPtr handler, Plugin* plugin)
	{
	DBG_LOG(DBG_PLUGINS, "Plugin %s requested event %s",
	        plugin->Name().c_str(), handler->Name());
	handler->SetGenerateAlways();
	}

void Manager::RequestBroObjDtor(BroObj* obj, Plugin* plugin)
	{
	obj->NotifyPluginsOnDtor();
	}

int Manager::HookLoadFile(const string& file)
	{
	HookArgumentList args;

	if ( HavePluginForHook(META_HOOK_PRE) )
		{
		args.push_back(HookArgument(file));
		MetaHookPre(HOOK_LOAD_FILE, args);
		}

	hook_list* l = hooks[HOOK_LOAD_FILE];

	size_t i = file.find_last_of("./");

	string ext;
	string normalized_file = file;

	if ( i != string::npos && file[i] == '.' )
		ext = file.substr(i + 1);
	else
		{
		// Add .bro as default extension.
		normalized_file = file + ".bro";
		ext = "bro";
		}

	int rc = -1;

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;

			rc = p->HookLoadFile(normalized_file, ext);

			if ( rc >= 0 )
				break;
			}

	if ( HavePluginForHook(META_HOOK_POST) )
		MetaHookPost(HOOK_LOAD_FILE, args, HookArgument(rc));

	return rc;
	}

std::pair<bool, Val*> Manager::HookCallFunction(const Func* func, Frame* parent, val_list* vargs) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(META_HOOK_PRE) )
		{
		args.push_back(HookArgument(func));
		args.push_back(HookArgument(parent));
		args.push_back(HookArgument(vargs));
		MetaHookPre(HOOK_CALL_FUNCTION, args);
		}

	hook_list* l = hooks[HOOK_CALL_FUNCTION];

	std::pair<bool, Val*> v = std::pair<bool, Val*>(false, NULL);

	if ( l )
		{
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;

			v = p->HookCallFunction(func, parent, vargs);

			if ( v.first )
				break;
			}
		}

	if ( HavePluginForHook(META_HOOK_POST) )
		MetaHookPost(HOOK_CALL_FUNCTION, args, HookArgument(v));

	return v;
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

void Manager::HookSetupAnalyzerTree(Connection *conn) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(META_HOOK_PRE) )
		{
		args.push_back(conn);
		MetaHookPre(HOOK_SETUP_ANALYZER_TREE, args);
		}

	hook_list *l = hooks[HOOK_SETUP_ANALYZER_TREE];

	if ( l )
		{
		for (hook_list::iterator i = l->begin() ; i != l->end(); ++i)
			{
			Plugin *p = (*i).second;
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
		args.push_back(network_time);
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
		args.push_back(obj);
		MetaHookPre(HOOK_BRO_OBJ_DTOR, args);
		}

	hook_list* l = hooks[HOOK_BRO_OBJ_DTOR];

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;
			p->HookBroObjDtor(obj);
			}

	if ( HavePluginForHook(META_HOOK_POST) )
		MetaHookPost(HOOK_BRO_OBJ_DTOR, args, HookArgument());
	}

void Manager::MetaHookPre(HookType hook, const HookArgumentList& args) const
	{
	hook_list* l = hooks[HOOK_CALL_FUNCTION];

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;
			p->MetaHookPre(hook, args);
			}
	}

void Manager::MetaHookPost(HookType hook, const HookArgumentList& args, HookArgument result) const
	{
	hook_list* l = hooks[HOOK_CALL_FUNCTION];

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;
			p->MetaHookPost(hook, args, result);
			}
	}
