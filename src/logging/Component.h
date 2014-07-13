// See the file "COPYING" in the main distribution directory for copyright.

#ifndef LOGGING_COMPONENT_H
#define LOGGING_COMPONENT_H

#include "Tag.h"
#include "plugin/Component.h"
#include "plugin/TaggedComponent.h"

namespace logging {

class WriterFrontend;
class WriterBackend;

/**
 * Component description for plugins providing log writers.
 */
class Component : public plugin::Component,
		  public plugin::TaggedComponent<logging::Tag> {
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
	~Component();

	/**
	 * Returns the writer's factory function.
	 */
	factory_callback Factory() const	{ return factory; }

protected:
	/**
	  * Overriden from plugin::Component.
	  */
	virtual void DoDescribe(ODesc* d) const;

private:
	factory_callback factory;
};

}

#endif
