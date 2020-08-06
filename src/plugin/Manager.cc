// See the file "COPYING" in the main distribution directory for copyright.

#include <optional>
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
#include "../Val.h"
#include "../util.h"
#include "../input.h"

using namespace std;
using namespace zeek::plugin;

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

	delete [] hooks;
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

	if ( ! zeek::util::is_dir(dir) )
		{
		DBG_LOG(zeek::DBG_PLUGINS, "Not a valid plugin directory: %s", dir.c_str());
		return;
		}

	// Check if it's a plugin dirctory.

	const std::string magic = dir + "/__bro_plugin__";

	if ( zeek::util::is_file(magic) )
		{
		// It's a plugin, get it's name.
		std::ifstream in(magic.c_str());

		if ( in.fail() )
			reporter->FatalError("cannot open plugin magic file %s", magic.c_str());

		std::string name;
		std::getline(in, name);
		zeek::util::strstrip(name);
		string lower_name = zeek::util::strtolower(name);

		if ( name.empty() )
			reporter->FatalError("empty plugin magic file %s", magic.c_str());

		if ( dynamic_plugins.find(lower_name) != dynamic_plugins.end() )
			{
			DBG_LOG(zeek::DBG_PLUGINS, "Found already known plugin %s in %s, ignoring", name.c_str(), dir.c_str());
			return;
			}

		// Record it, so that we can later activate it.
		dynamic_plugins.insert(std::make_pair(lower_name, dir));

		DBG_LOG(zeek::DBG_PLUGINS, "Found plugin %s in %s", name.c_str(), dir.c_str());
		return;
		}

	// No plugin here, traverse subirectories.

	DIR* d = opendir(dir.c_str());

	if ( ! d )
		{
		DBG_LOG(zeek::DBG_PLUGINS, "Cannot open directory %s", dir.c_str());
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
			DBG_LOG(zeek::DBG_PLUGINS, "Cannot stat %s: %s", path.c_str(), strerror(errno));
			continue;
			}

		if ( st.st_mode & S_IFDIR )
			SearchDynamicPlugins(path);
		}

	closedir(d);
	}

bool Manager::ActivateDynamicPluginInternal(const std::string& name, bool ok_if_not_found)
	{
	dynamic_plugin_map::iterator m = dynamic_plugins.find(zeek::util::strtolower(name));

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

	if ( m->second.empty() )
		{
		// That's our marker that we have already activated this
		// plugin. Silently ignore the new request.
		return true;
		}

	std::string dir = m->second + "/";

	DBG_LOG(zeek::DBG_PLUGINS, "Activating plugin %s", name.c_str());

	// Add the "scripts" and "bif" directories to ZEEKPATH.
	std::string scripts = dir + "scripts";

	if ( zeek::util::is_dir(scripts) )
		{
		DBG_LOG(zeek::DBG_PLUGINS, "  Adding %s to ZEEKPATH", scripts.c_str());
		zeek::util::add_to_zeek_path(scripts);
		}

	string init;

	// First load {scripts}/__preload__.zeek automatically.
	for (const string& ext : zeek::util::script_extensions)
		{
		init = dir + "scripts/__preload__" + ext;

		if ( zeek::util::is_file(init) )
			{
			DBG_LOG(zeek::DBG_PLUGINS, "  Loading %s", init.c_str());
			zeek::util::warn_if_legacy_script(init);
			scripts_to_load.push_back(init);
			break;
			}
		}

	// Load {bif,scripts}/__load__.zeek automatically.
	for (const string& ext : zeek::util::script_extensions)
		{
		init = dir + "lib/bif/__load__" + ext;

		if ( zeek::util::is_file(init) )
			{
			DBG_LOG(zeek::DBG_PLUGINS, "  Loading %s", init.c_str());
			zeek::util::warn_if_legacy_script(init);
			scripts_to_load.push_back(init);
			break;
			}
		}

	for (const string& ext : zeek::util::script_extensions)
		{
		init = dir + "scripts/__load__" + ext;

		if ( zeek::util::is_file(init) )
			{
			DBG_LOG(zeek::DBG_PLUGINS, "  Loading %s", init.c_str());
			zeek::util::warn_if_legacy_script(init);
			scripts_to_load.push_back(init);
			break;
			}
		}

	// Load shared libraries.

	string dypattern = dir + "/lib/*." + HOST_ARCHITECTURE + DYNAMIC_PLUGIN_SUFFIX;

	DBG_LOG(zeek::DBG_PLUGINS, "  Searching for shared libraries %s", dypattern.c_str());

	glob_t gl;

	if ( glob(dypattern.c_str(), 0, 0, &gl) == 0 )
		{
		for ( size_t i = 0; i < gl.gl_pathc; i++ )
			{
			const char* path = gl.gl_pathv[i];

			current_plugin = nullptr;
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
			DBG_LOG(zeek::DBG_PLUGINS, "  InitialzingComponents");
			current_plugin->InitializeComponents();

			plugins_by_path.insert(std::make_pair(zeek::util::normalize_path(dir), current_plugin));

			// We execute the pre-script initialization here; this in
			// fact could be *during* script initialization if we got
			// triggered via @load-plugin.
			current_plugin->InitPreScript();

			// Make sure the name the plugin reports is consistent with
			// what we expect from its magic file.
			if ( zeek::util::strtolower(current_plugin->Name()) != zeek::util::strtolower(name) )
				reporter->FatalError("inconsistent plugin name: %s vs %s",
						     current_plugin->Name().c_str(), name.c_str());

			current_dir = nullptr;
			current_sopath = nullptr;
			current_plugin = nullptr;

			DBG_LOG(zeek::DBG_PLUGINS, "  Loaded %s", path);
			}

		globfree(&gl);
		}

	else
		{
		DBG_LOG(zeek::DBG_PLUGINS, "  No shared library found");
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
	zeek::util::tokenize_string(zeek::util::zeek_plugin_activate(), ",", &p);

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
	return zeek::util::strtolower(a->Name()) < zeek::util::strtolower(b->Name());
	}

void Manager::RegisterPlugin(Plugin *plugin)
	{
	Manager::ActivePluginsInternal()->push_back(plugin);

	if ( current_dir && current_sopath )
		// A dynamic plugin, record its location.
		plugin->SetPluginLocation(zeek::util::normalize_path(current_dir), current_sopath);

	current_plugin = plugin;
	}

void Manager::RegisterBifFile(const char* plugin, bif_init_func c)
	{
	bif_init_func_map* bifs = BifFilesInternal();

	std::string lower_plugin = zeek::util::strtolower(plugin);
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
		bif_init_func_map::const_iterator b = bifs->find(zeek::util::strtolower((*i)->Name()));

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
			if ( (*i).first == zeek::util::strtolower((*j)->Name()) )
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
	auto path = zeek::util::normalize_path(_path);

	if ( zeek::util::is_file(path) )
		path = zeek::util::SafeDirname(path).result;

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
		return zeek::util::strtolower(a.second->Name()) < zeek::util::strtolower(a.second->Name());

	// Reverse sort.
	return a.first > b.first;
	}

std::list<std::pair<zeek::plugin::HookType, int> > Manager::HooksEnabledForPlugin(const Plugin* plugin) const
	{
	std::list<std::pair<zeek::plugin::HookType, int> > enabled;

	for ( int i = 0; i < NUM_HOOKS; i++ )
		{
		if ( hook_list* l = hooks[i] )
			for ( const auto& [hook, hook_plugin] : *l )
				if ( hook_plugin == plugin )
					enabled.push_back(std::make_pair(static_cast<zeek::plugin::HookType>(i), hook));
		}

	return enabled;
	}

void Manager::EnableHook(zeek::plugin::HookType hook, Plugin* plugin, int prio)
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

void Manager::DisableHook(zeek::plugin::HookType hook, Plugin* plugin)
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
	DBG_LOG(zeek::DBG_PLUGINS, "Plugin %s requested event %s",
	        plugin->Name().c_str(), handler->Name());
	handler->SetGenerateAlways();
	}

void Manager::RequestBroObjDtor(Obj* obj, Plugin* plugin)
	{
	obj->NotifyPluginsOnDtor();
	}

int Manager::HookLoadFile(const Plugin::LoadType type, const string& file, const string& resolved)
	{
	HookArgumentList args;

	if ( HavePluginForHook(zeek::plugin::META_HOOK_PRE) )
		{
		args.push_back(HookArgument(type));
		args.push_back(HookArgument(file));
		args.push_back(HookArgument(resolved));
		MetaHookPre(zeek::plugin::HOOK_LOAD_FILE, args);
		}

	hook_list* l = hooks[zeek::plugin::HOOK_LOAD_FILE];

	int rc = -1;

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;

			rc = p->HookLoadFile(type, file, resolved);

			if ( rc >= 0 )
				break;
			}

	if ( HavePluginForHook(zeek::plugin::META_HOOK_POST) )
		MetaHookPost(zeek::plugin::HOOK_LOAD_FILE, args, HookArgument(rc));

	return rc;
	}

std::pair<bool, zeek::ValPtr>
Manager::HookCallFunction(const zeek::Func* func, zeek::detail::Frame* parent,
                          zeek::Args* vecargs) const
	{
	HookArgumentList args;
	val_list vargs;

	if ( HavePluginForHook(zeek::plugin::META_HOOK_PRE) )
		{
		vargs.resize(vecargs->size());

		for ( const auto& v : *vecargs )
			vargs.push_back(v.get());

		args.push_back(HookArgument(func));
		args.push_back(HookArgument(parent));
		args.push_back(HookArgument(&vargs));
		MetaHookPre(zeek::plugin::HOOK_CALL_FUNCTION, args);
		}

	hook_list* l = hooks[zeek::plugin::HOOK_CALL_FUNCTION];

	std::pair<bool, zeek::ValPtr> rval{false, nullptr};

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

	if ( HavePluginForHook(zeek::plugin::META_HOOK_POST) )
		MetaHookPost(zeek::plugin::HOOK_CALL_FUNCTION, args,
		             HookArgument(std::make_pair(rval.first, rval.second.get())));

	return rval;
	}

bool Manager::HookQueueEvent(Event* event) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(zeek::plugin::META_HOOK_PRE) )
		{
		args.push_back(HookArgument(event));
		MetaHookPre(zeek::plugin::HOOK_QUEUE_EVENT, args);
		}

	hook_list* l = hooks[zeek::plugin::HOOK_QUEUE_EVENT];

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

	if ( HavePluginForHook(zeek::plugin::META_HOOK_POST) )
		MetaHookPost(zeek::plugin::HOOK_QUEUE_EVENT, args, HookArgument(result));

	return result;
	}

void Manager::HookDrainEvents() const
	{
	HookArgumentList args;

	if ( HavePluginForHook(zeek::plugin::META_HOOK_PRE) )
		MetaHookPre(zeek::plugin::HOOK_DRAIN_EVENTS, args);

	hook_list* l = hooks[zeek::plugin::HOOK_DRAIN_EVENTS];

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;
			p->HookDrainEvents();
			}

	if ( HavePluginForHook(zeek::plugin::META_HOOK_POST) )
		MetaHookPost(zeek::plugin::HOOK_DRAIN_EVENTS, args, HookArgument());

	}

void Manager::HookSetupAnalyzerTree(Connection *conn) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(zeek::plugin::META_HOOK_PRE) )
		{
		args.push_back(HookArgument(conn));
		MetaHookPre(zeek::plugin::HOOK_SETUP_ANALYZER_TREE, args);
		}

	hook_list *l = hooks[zeek::plugin::HOOK_SETUP_ANALYZER_TREE];

	if ( l )
		{
		for (hook_list::iterator i = l->begin() ; i != l->end(); ++i)
			{
			Plugin *p = (*i).second;
			p->HookSetupAnalyzerTree(conn);
			}
		}

	if ( HavePluginForHook(zeek::plugin::META_HOOK_POST) )
		{
		MetaHookPost(zeek::plugin::HOOK_SETUP_ANALYZER_TREE, args, HookArgument());
		}
	}

void Manager::HookUpdateNetworkTime(double network_time) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(zeek::plugin::META_HOOK_PRE) )
		{
		args.push_back(HookArgument(network_time));
		MetaHookPre(zeek::plugin::HOOK_UPDATE_NETWORK_TIME, args);
		}

	hook_list* l = hooks[zeek::plugin::HOOK_UPDATE_NETWORK_TIME];

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;
			p->HookUpdateNetworkTime(network_time);
			}

	if ( HavePluginForHook(zeek::plugin::META_HOOK_POST) )
		MetaHookPost(zeek::plugin::HOOK_UPDATE_NETWORK_TIME, args, HookArgument());
	}

void Manager::HookBroObjDtor(void* obj) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(zeek::plugin::META_HOOK_PRE) )
		{
		args.push_back(HookArgument(obj));
		MetaHookPre(zeek::plugin::HOOK_BRO_OBJ_DTOR, args);
		}

	hook_list* l = hooks[zeek::plugin::HOOK_BRO_OBJ_DTOR];

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;
			p->HookBroObjDtor(obj);
			}

	if ( HavePluginForHook(zeek::plugin::META_HOOK_POST) )
		MetaHookPost(zeek::plugin::HOOK_BRO_OBJ_DTOR, args, HookArgument());
	}

void Manager::HookLogInit(const std::string& writer,
                          const std::string& instantiating_filter,
                          bool local, bool remote,
                          const logging::WriterBackend::WriterInfo& info,
                          int num_fields,
                          const threading::Field* const* fields) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(zeek::plugin::META_HOOK_PRE) )
		{
		args.push_back(HookArgument(writer));
		args.push_back(HookArgument(instantiating_filter));
		args.push_back(HookArgument(local));
		args.push_back(HookArgument(remote));
		args.push_back(HookArgument(&info));
		args.push_back(HookArgument(num_fields));
		args.push_back(HookArgument(std::make_pair(num_fields, fields)));
		MetaHookPre(zeek::plugin::HOOK_LOG_INIT, args);
		}

	hook_list* l = hooks[zeek::plugin::HOOK_LOG_INIT];

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;
			p->HookLogInit(writer, instantiating_filter, local, remote, info,
			               num_fields, fields);
			}

	if ( HavePluginForHook(zeek::plugin::META_HOOK_POST) )
		MetaHookPost(zeek::plugin::HOOK_LOG_INIT, args, HookArgument());
	}

bool Manager::HookLogWrite(const std::string& writer,
                           const std::string& filter,
                           const logging::WriterBackend::WriterInfo& info,
                           int num_fields,
                           const threading::Field* const* fields,
                           threading::Value** vals) const
	{
	HookArgumentList args;

	if ( HavePluginForHook(zeek::plugin::META_HOOK_PRE) )
		{
		args.push_back(HookArgument(writer));
		args.push_back(HookArgument(filter));
		args.push_back(HookArgument(&info));
		args.push_back(HookArgument(num_fields));
		args.push_back(HookArgument(std::make_pair(num_fields, fields)));
		args.push_back(HookArgument(vals));
		MetaHookPre(zeek::plugin::HOOK_LOG_WRITE, args);
		}

	hook_list* l = hooks[zeek::plugin::HOOK_LOG_WRITE];

	bool result = true;

	if ( l )
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;

			if ( ! p->HookLogWrite(writer, filter, info, num_fields, fields,
			                       vals) )
				{
				result = false;
				break;
				}
			}

	if ( HavePluginForHook(zeek::plugin::META_HOOK_POST) )
		MetaHookPost(zeek::plugin::HOOK_LOG_WRITE, args, HookArgument(result));

	return result;
	}

bool Manager::HookReporter(const std::string& prefix, const EventHandlerPtr event,
                           const zeek::Connection* conn, const val_list* addl, bool location,
                           const zeek::detail::Location* location1,
                           const zeek::detail::Location* location2,
                           bool time, const std::string& message)

	{
	HookArgumentList args;

	if ( HavePluginForHook(zeek::plugin::META_HOOK_PRE) )
		{
		args.push_back(HookArgument(prefix));
		args.push_back(HookArgument(conn));
		args.push_back(HookArgument(addl));
		args.push_back(HookArgument(location1));
		args.push_back(HookArgument(location2));
		args.push_back(HookArgument(location));
		args.push_back(HookArgument(time));
		args.push_back(HookArgument(message));
		MetaHookPre(zeek::plugin::HOOK_REPORTER, args);
		}

	hook_list* l = hooks[zeek::plugin::HOOK_REPORTER];

	bool result = true;

	if ( l )
		{
		for ( hook_list::iterator i = l->begin(); i != l->end(); ++i )
			{
			Plugin* p = (*i).second;

			if ( ! p->HookReporter(prefix, event, conn, addl, location, location1, location2, time, message) )
				{
				result = false;
				break;
				}
			}
		}

	if ( HavePluginForHook(zeek::plugin::META_HOOK_POST) )
		MetaHookPost(zeek::plugin::HOOK_REPORTER, args, HookArgument(result));

	return result;
	}


void Manager::MetaHookPre(zeek::plugin::HookType hook, const HookArgumentList& args) const
	{
	if ( hook_list* l = hooks[zeek::plugin::HOOK_CALL_FUNCTION] )
		for ( const auto& [hook_type, plugin] : *l )
			plugin->MetaHookPre(hook, args);
	}

void Manager::MetaHookPost(zeek::plugin::HookType hook, const HookArgumentList& args, HookArgument result) const
	{
	if ( hook_list* l = hooks[zeek::plugin::HOOK_CALL_FUNCTION] )
		for ( const auto& [hook_type, plugin] : *l )
			plugin->MetaHookPost(hook, args, result);
	}
