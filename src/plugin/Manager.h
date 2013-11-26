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
	(plugin_mgr->HavePluginForHook(plugin::hook) ? plugin_mgr->method_call : (default_result))

#define PLUGIN_HOOK_VOID(hook, method_call) \
	if ( plugin_mgr->HavePluginForHook(plugin::hook) ) plugin_mgr->method_call;

/**
 * A singleton object managing all plugins.
 */
class Manager
{
public:
	typedef std::list<Plugin*> plugin_list;
	typedef Plugin::component_list component_list;

	/**
	 * Constructor.
	 */
	Manager();

	/**
	 * Destructor.
	 */
	virtual ~Manager();

	/**
	 * Loads all plugins dynamically from a set of directories. Multiple
	 * directories are split by ':'. If a directory does not contain a
	 * plugin itself, the method searches for plugins recursively. For
	 * plugins found, the method loads the plugin's shared library and
	 * makes its scripts available to the interpreter.
	 *
	 * This must be called only before InitPluginsPreScript().
	 *
	 * @param dir The directory to search for plugins.
	 */
	void LoadPluginsFrom(const std::string& dir);

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
	 * Returns a list of all available plugins. This includes all that
	 * are compiled in statically, as well as those loaded dynamically so
	 * far.
	 */
	plugin_list Plugins() const;

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
	virtual int HookLoadFile(const char* file);

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
	 * Hooks that informs plugins that the event queue is being drained.
	 */
	void HookDrainEvents() const;

	/**
	 * Internal method that registers a freshly instantiated plugin with
	 * the manager.
	 *
	 * @param plugin The plugin to register. The method does not take
	 * ownership, yet assumes the pointer will stay valid at least until
	 * the Manager is destroyed.
	 */
	static bool RegisterPlugin(Plugin* plugin);

protected:
	/**
	 * Loads a plugin dynamically from a given directory. It loads the
	 * plugin's shared library, and makes its scripts available to the
	 * interpreter. Different from LoadPluginsFrom() this method does not
	 * further descend the directory tree recursively to search for
	 * plugins.
	 *
	 * This must be called only before InitPluginsPreScript()
	 *
	 * @param file The path to the plugin to load.
	 *
	 * @return 0 if there's a plugin in this directory, but there was a
	 * problem loading it; -1 if there's no plugin at all in this
	 * directory; 1 if there's a plugin in this directory and we loaded
	 * it successfully.
	 */
	int LoadPlugin(const std::string& dir);

private:
	// A hook list keeps pairs of plugin and priority interested in a
	// given hook.
	typedef std::list<std::pair<int, Plugin*> > hook_list;

	static plugin_list* PluginsInternal();

	bool init;

	// An array indexed by HookType. An entry is null if there's no hook
	// of that type enabled.
	hook_list** hooks;

	static string current_dir;
	static string current_sopath;
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

}

/**
 * The global plugin manager singleton.
 */
extern plugin::Manager* plugin_mgr;

#endif
