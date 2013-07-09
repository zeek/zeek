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
	 * Loads a plugin dynamically from a file. This must be called only
	 * before InitPluginsPreScript()
	 *
	 * This is not currently implemented.
	 *
	 * @param file The path to the plugin to load.
	 */
	bool LoadPlugin(const std::string& file);

	/**
	 * Loads plugins dynamically found in a directory. This must be
	 * called only before InitPluginsPreScript().
	 *
	 * This is not currently implemented.
	 *
	 * @param dir The directory to search for plugins.
	 */
	bool LoadPluginsFrom(const std::string& dir);

	/**
	 * First-stage initializion of the manager. This is called early on
	 * during Bro's initialization, before any scripts are processed, and
	 * forwards to the corresponding Plugin methods.
	 */
	void InitPreScript();

	/**
	 * Second-stage initialization of the manager. This is called late
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

private:
	static plugin_list* PluginsInternal();

	bool init;
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
