// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Tag.h"
#include "zeek/plugin/Component.h"

namespace zeek::logging
	{

class WriterFrontend;
class WriterBackend;

/**
 * Component description for plugins providing log writers.
 */
class Component : public plugin::Component
	{
public:
	using factory_callback = WriterBackend* (*)(WriterFrontend* frontend);

	/**
	 * Constructor.
	 *
	 * @param name The name of the provided writer. This name is used
	 * across the system to identify the writer.
	 *
	 * @param factory A factory function to instantiate instances of the
	 * writers's class, which must be derived directly or indirectly from
	 * logging::WriterBackend. This is typically a static \c Instantiate()
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
	factory_callback Factory() const { return factory; }

protected:
	/**
	 * Overriden from plugin::Component.
	 */
	void DoDescribe(ODesc* d) const override;

private:
	factory_callback factory;
	};

	} // namespace zeek::logging
