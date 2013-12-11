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

	/**
	 * XXX
	 */
	virtual const char* Name() const	{ return name.c_str(); }

	/**
	 * Generates a human-readable description of the component. This goes
	 * into the output of \c "bro -NN".
	 */
	virtual void Describe(ODesc* d) const;

	Component& operator=(const Component& other);

protected:
	Component(plugin::component::Type type, const std::string& name);

private:
	std::string name;
};

}

#endif
