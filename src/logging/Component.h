// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Tag.h"
#include "plugin/Component.h"
#include "plugin/TaggedComponent.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(WriterFrontend, zeek, logging);
ZEEK_FORWARD_DECLARE_NAMESPACED(WriterBackend, zeek, logging);

namespace zeek::logging {

/**
 * Component description for plugins providing log writers.
 */
class Component : public zeek::plugin::Component,
                  public zeek::plugin::TaggedComponent<logging::Tag> {
public:
	typedef WriterBackend* (*factory_callback)(WriterFrontend* frontend);

	/**
	 * Constructor.
	 *
	 * @param name The name of the provided writer. This name is used
	 * across the system to identify the writer.
	 *
	 * @param factory A factory function to instantiate instances of the
	 * writers's class, which must be derived directly or indirectly from
	 * logging::WriterBackend. This is typically a static \c Instatiate()
	 * method inside the class that just allocates and returns a new
	 * instance.
	 */
	Component(const std::string& name, factory_callback factory);

	/**
	 * Destructor.
	 */
	~Component() override;

	/**
	 * Initialization function. This function has to be called before any
	 * plugin component functionality is used; it is used to add the
	 * plugin component to the list of components and to initialize tags
	 */
	void Initialize() override;

	/**
	 * Returns the writer's factory function.
	 */
	factory_callback Factory() const	{ return factory; }

protected:
	/**
	  * Overriden from plugin::Component.
	  */
	void DoDescribe(zeek::ODesc* d) const override;

private:
	factory_callback factory;
};

} // namespace zeek::logging
