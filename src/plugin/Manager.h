
#ifndef PLUGIN_MANAGER_H
#define PLUGIN_MANAGER_H

#include "Plugin.h"
#include "Component.h"

#include "../Reporter.h"

namespace plugin {

class Manager
{
public:
	typedef std::list<Plugin*> plugin_list;
	typedef Plugin::component_list component_list;

	Manager();
	~Manager();

	/**
	 */
	bool LoadPlugin(const std::string& file);

	/**
	 *
	 */
	bool LoadPluginsFrom(const std::string& dir);

	/**
	 *
	 * @param plugin: The plugin to register. The method does not take
	 * ownershop but assume the pointer will leave at least until the
	 * Manager is destroyed.
	 */
	static bool RegisterPlugin(Plugin *plugin);

	/**
	 *
	 */
	void InitPlugins();

	/**
	 *
	 */
	void InitPluginsBif();

	/**
	 *
	 */
	void FinishPlugins();

	/**
	 *
	 */
	plugin_list Plugins() const;

	/**
	 *
	 */
	template<class T>
	std::list<T *> Components(component::Type type) const;

private:
	static plugin_list* PluginsInternal();

	bool init;
};

template<class T>
std::list<T *> Manager::Components(component::Type type) const
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

extern plugin::Manager* plugin_mgr;

#endif
