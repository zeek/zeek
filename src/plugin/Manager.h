// See the file "COPYING" in the main distribution directory for copyright.

#ifndef PLUGIN_MANAGER_H
#define PLUGIN_MANAGER_H

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
	 * Internal method that registers a freshly instantiated plugin with
	 * the manager.
	 *
	 * @param plugin The plugin to register. The method does not take
	 * ownership, yet assumes the pointer will stay valid at least until
	 * the Manager is destroyed.
	 */
	static bool RegisterPlugin(Plugin *plugin);

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
