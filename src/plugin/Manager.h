// See the file "COPYING" in the main distribution directory for copyright.

#ifndef PLUGIN_MANAGER_H
#define PLUGIN_MANAGER_H

#include <map>

#include "Plugin.h"
#include "Component.h"

#include "../Reporter.h"

namespace plugin {

/**
 * A singleton object managing all plugins.
 */
class Manager
{
public:
	typedef std::list<Plugin*> plugin_list;
	typedef std::list<InterpreterPlugin*> interpreter_plugin_list;
	typedef Plugin::component_list component_list;

	/**
	 * Constructor.
	 */
	Manager();

	/**
	 * Destructor.
	 */
	~Manager();

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
	 * This tries to load the given file by searching for a plugin that
	 * support that extension. If a correspondign plugin is found, it's
	 * asked to loead the file. If that fails, the method reports an 
	 * error message.
	 *
	 * This method must be called only between InitPreScript() and
	 * InitPostScript().
	 *
	 * @return 1 if the file was sucessfully loaded by a plugin; 0 if a
	 * plugin was found that supports the file's extension, yet it
	 * encountered a problem loading the file; and -1 if we don't have a
	 * plugin that supports this extension.
	 */
	int TryLoadFile(const char* file);

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
	 * Filters a function/event/hook call through all interpreter plugins.
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
	Val* CallFunction(const Func* func, val_list* args) const;

    /**
     * Filter the queuing of an event through all interpreter plugins.
     *
     * @param event The event to be queued; it may be modified.
     *
     * @return Returns true if a plugin handled the queuing; in that case the
     * plugin will have taken ownership.
	 *
     */
	bool QueueEvent(Event* event) const;

	/**
	 * Informs all interpreter plugins about an update in network time.
	 *
	 * @param networkt_time The new network time.
	 */
	void UpdateNetworkTime(double network_time) const;

	/**
	 * Informs all interpreter plugins that the event queue has been drained.
	 */
	void DrainEvents() const;

	/**
	 * Informs all interpreter plugins that a new connection has been instantiated.
	 */
	void NewConnection(const Connection* c) const;

	/**
	 * Informs all interpreter plugins that a connection is about to go away.
	 */
	void ConnectionStateRemove(const Connection* c) const;

	/**
	 * Disables an interpreter plugin's hooking of the script interpreter.
	 * The remaining functionality of the Plugin base class remains
	 * available.
	 *
	 * @param plugin The plugin to disable.
	 */
	void DisableInterpreterPlugin(const InterpreterPlugin* plugin);

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
	static plugin_list* PluginsInternal();

	bool init;
	typedef std::map<std::string, Plugin*> extension_map;
	extension_map extensions;

	interpreter_plugin_list interpreter_plugins;

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
