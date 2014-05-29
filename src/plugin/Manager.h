// See the file "COPYING" in the main distribution directory for copyright.

#ifndef PLUGIN_MANAGER_H
#define PLUGIN_MANAGER_H

#include <map>

#include "Plugin.h"
#include "Component.h"

#include "../Reporter.h"

namespace plugin {

// Macros that trigger a plugin hook. We put this into macros to short-cut
// the code for the most common case that no plugin defines the hook.
#define PLUGIN_HOOK_WITH_RESULT(hook, method_call, default_result) \
   (plugin_mgr->HavePluginForHook(::plugin::hook) ? plugin_mgr->method_call : (default_result))

#define PLUGIN_HOOK_VOID(hook, method_call) \
	if ( plugin_mgr->HavePluginForHook(plugin::hook) ) plugin_mgr->method_call;


/**
 * A singleton object managing all plugins.
 */
class Manager
{
public:
	typedef void (*bif_init_func)(Plugin *);
	typedef std::list<Plugin*> plugin_list;
	typedef Plugin::component_list component_list;
	typedef std::list<std::pair<std::string, std::string> > inactive_plugin_list;

	/**
	 * Constructor.
	 */
	Manager();

	/**
	 * Destructor.
	 */
	virtual ~Manager();

	/**
	 * Searches a set of directories for plugins. If a specificed
	 * directory does not contain a plugin itself, the method searches
	 * for plugins recursively. For plugins found, the method makes them
	 * available for later activation via ActivatePlugin().
	 *
	 * This must be called only before InitPluginsPreScript().
	 *
	 * @param dir The directory to search for plugins. Multiple
	 * directories are split by ':'.
	 */
	void SearchDynamicPlugins(const std::string& dir);

	/**
	 * Activates a plugin that SearchPlugins() has previously discovered.
	 * Activing a plugin involved loading its dynamic module, making its
	 * bifs available, and adding its script paths to BROPATH.
	 *
	 * @param name The name of the plugin, as determined previously by
	 * SearchPlugin().
	 *
	 * @return True if the plugin has been loaded successfully.
	 *
	 */
	bool ActivateDynamicPlugin(const std::string& name);

	/**
	 * Activates plugins that SearchPlugins() has previously discovered. The
	 * effect is the same all calling \a ActivePlugin(name) for the plugins.
	 *
	 * @param all If true, activates all plugins that are found. If false,
	 * activate only those that should always be activated unconditionally
	 * via the BRO_PLUGIN_ACTIVATE enviroment variable. In other words, it's
	 * false if running bare mode.
	 *
	 * @return True if all plugins have been loaded successfully. If one
	 * fail to load, the method stops there without loading any furthers
	 * and returns false.
	 */
	bool ActivateDynamicPlugins(bool all);

	/**
	 * First-stage initializion of the manager. This is called early on
	 * during Bro's initialization, before any scripts are processed, and
	 * forwards to the corresponding Plugin methods.
	 */
	void InitPreScript();

	/**
	 * Second-stage initialization of the manager. This is called in
	 * between pre- and post-script to make BiFs available.
	 */
	void InitBifs();

	/**
	 * Third-stage initialization of the manager. This is called late
	 * during Bro's initialization after any scripts are processed, and
	 * forwards to the corresponding Plugin methods.
	 */
	void InitPostScript();

	/**
	 * Finalizes all plugins at termination time. This forwards to the
	 * corresponding Plugin methods.
	 */
	void FinishPlugins();

	/**
	 * Returns a list of all available and activated plugins. This includes
	 * all that are compiled in statically, as well as those loaded
	 * dynamically so far.
	 */
	plugin_list Plugins() const;

	/**
	 * Returns a list of all dynamic plugins that have been found, yet not
	 * activated. The returned list contains pairs of plugin name and base
	 * directory. Note that because they aren't activated, that's all
	 * information we have access to.
	 */
	inactive_plugin_list InactivePlugins() const;

	/**
	 * Returns a list of all available components, in any plugin, that
	 * are derived from a specific class. The class is given as the
	 * template parameter \c T.
	 */
	template<class T> std::list<T *> Components() const;

	/**
	 * Returns true if there's at least one plugin interested in a given
	 * hook.
	 *
	 * @param The hook to check.
	 *
	 * @return True if there's a plugin for that hook.
	 */
	bool HavePluginForHook(HookType hook) const
		{
		// Inline to make avoid the function call.
		return hooks[hook] != 0;
		}

	/**
	 * Returns all the hooks, with their priorities, that are currently
	 * enabled for a given plugin.
	 *
	 * @param plugin The plugin to return the hooks for.
	 */
	std::list<std::pair<HookType, int> > HooksEnabledForPlugin(const Plugin* plugin) const;

	/**
	 * Enables a hook for a given plugin.
	 *
	 * hook: The hook to enable.
	 *
	 * plugin: The plugin defining the hook.
	 *
	 * prio: The priority to associate with the plugin for this hook.
	 */
	void EnableHook(HookType hook, Plugin* plugin, int prio);

	/**
	 * Disables a hook for a given plugin.
	 *
	 * hook: The hook to enable.
	 *
	 * plugin: The plugin that used to define the hook.
	 */
	void DisableHook(HookType hook, Plugin* plugin);

	/**
	 * Register interest in an event. The event will then be raised, and
	 * hence passed to the plugin, even if there no handler defined.
	 *
	 * @param handler The event being interested in.
	 *
	 * @param plugin The plugin expressing interest.
	 */
	void RequestEvent(EventHandlerPtr handler, Plugin* plugin);

	/**
	 * Register interest in the destruction of a BroObj instance. When
	 * Bro's reference counting triggers the objects destructor to run,
	 * the \a HookBroObjDtor will be called.
	 *
	 * @param handler The object being interested in.
	 *
	 * @param plugin The plugin expressing interest.
	 */
	void RequestBroObjDtor(BroObj* obj, Plugin* plugin);

	// Hook entry functions.

	/**
	 * Hook that gives plugins a chance to take over loading an input
	 * input file. This method must be called between InitPreScript() and
	 * InitPostScript() for each input file Bro is about to load, either
	 * given on the command line or via @load script directives. The hook
	 * can take over the file, in which case Bro must not further process
	 * it otherwise.
	 *
	 * @return 1 if a plugin took over the file and loaded it
	 * successfully; 0 if a plugin took over the file but had trouble
	 * loading it; and -1 if no plugin was interested in the file at all.
	 */
	virtual int HookLoadFile(const string& file);

	/**
	 * Hook that filters calls to a script function/event/hook.
	 *
	 * @param func The function to be called.
	 *
	 * @param args The function call's arguments; they may be modified.
	 *
	 * @return If a plugin handled the call, a +1 Val with the result
	 * value to pass back to the interpreter (for void functions and
	 * events, it may be any Val and must be ignored). If no plugin
	 * handled the call, the method returns null.
	 */
	Val* HookCallFunction(const Func* func, val_list* args) const;

	/**
	 * Hook that filters the queuing of an event.
	 *
	 * @param event The event to be queued; it may be modified.
	 *
	 * @return Returns true if a plugin handled the queuing; in that case
	 * the plugin will have taken ownership.
	 */
	bool HookQueueEvent(Event* event) const;

	/**
	 * Hook that informs plugins about an update in network time.
	 *
	 * @param network_time The new network time.
	 */
	void HookUpdateNetworkTime(double network_time) const;

	/**
	 * Hook that informs plugins that the event queue is being drained.
	 */
	void HookDrainEvents() const;

	/**
	 * Hook that informs plugins that an BroObj is being destroyed. Will be
	 * called only for objects that a plugin has expressed interest in.
	 */
	void HookBroObjDtor(void* obj) const;

	/**
	 * Internal method that registers a freshly instantiated plugin with
	 * the manager.
	 *
	 * @param plugin The plugin to register. The method does not take
	 * ownership, yet assumes the pointer will stay valid at least until
	 * the Manager is destroyed.
	 */
	static void RegisterPlugin(Plugin* plugin);

	/**
	 * Internal method that registers a bif file's init function for a plugin.
	 */
	static void RegisterBifFile(const char* plugin, bif_init_func c);

private:
	bool ActivateDynamicPluginInternal(const std::string& name, bool ok_if_not_found = false);
	void UpdateInputFiles();
	void MetaHookPre(HookType hook, const HookArgumentList& args) const;
	void MetaHookPost(HookType hook, const HookArgumentList& args, HookArgument result) const;

	 // All found dynamic plugins, mapping their names to base directory.
	typedef std::map<std::string, std::string> dynamic_plugin_map;
	dynamic_plugin_map dynamic_plugins;

	// We buffer scripts to load temporarliy to get them to load in the
	// right order.
	typedef std::list<std::string> file_list;
	file_list scripts_to_load;

	bool init;

	// A hook list keeps pairs of plugin and priority interested in a
	// given hook.
	typedef std::list<std::pair<int, Plugin*> > hook_list;

	// An array indexed by HookType. An entry is null if there's no hook
	// of that type enabled.
	hook_list** hooks;

	static Plugin* current_plugin;
	static string current_dir;
	static string current_sopath;

	// Returns a modifiable list of all plugins, both static and dynamic.
	// This is a static method so that plugins can register themselves
	// even before the manager exists.
	static plugin_list* PluginsInternal();

	typedef std::list<bif_init_func> bif_init_func_list;
	typedef std::map<std::string, bif_init_func_list*> bif_init_func_map;

	// Returns a modifiable map of all bif files. This is a static method
	// so that plugins can register their bifs even before the manager
	// exists.
	static bif_init_func_map* BifFilesInternal();
};

template<class T>
std::list<T *> Manager::Components() const
	{
	std::list<T *> result;

	for ( plugin_list::const_iterator p = PluginsInternal()->begin(); p != PluginsInternal()->end(); p++ )
		{
		component_list components = (*p)->Components();

		for ( component_list::const_iterator c = components.begin(); c != components.end(); c++ )
			{
			T* t = dynamic_cast<T *>(*c);

			if ( t )
				result.push_back(t);
			}
		}

	return result;
	}

/**
 * Internal class used by bifcl-generated code to register its init functions at runtime.
 */
class __RegisterBif {
public:
	__RegisterBif(const char* plugin, Manager::bif_init_func init)
		{
		Manager::RegisterBifFile(plugin, init);
		}
};

}

/**
 * The global plugin manager singleton.
 */
extern plugin::Manager* plugin_mgr;

#endif
