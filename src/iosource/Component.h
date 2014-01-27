// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IOSOURCE_PLUGIN_COMPONENT_H
#define IOSOURCE_PLUGIN_COMPONENT_H

#include "plugin/Component.h"

namespace iosource {

class IOSource;

/**
 * Component description for plugins providing IOSources.
 */
class Component : public plugin::Component {
public:
	typedef IOSource* (*factory_callback)();

	/**
	 * XXX
	 */
	Component(const std::string& name);

	/**
	 * Copy constructor.
	 */
	Component(const Component& other);

	/**
	 * Destructor.
	 */
	~Component();

protected:
    /**
     * XXXX
     */
	Component(plugin::component::Type type, const std::string& name);
};

}

#endif
