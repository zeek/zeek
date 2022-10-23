// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"

#include "zeek/Tag.h"
#include "zeek/plugin/Component.h"

namespace zeek
	{

class RecordVal;
using RecordValPtr = zeek::IntrusivePtr<RecordVal>;

namespace file_analysis
	{

class File;
class Analyzer;
class Manager;

/**
 * Component description for plugins providing file analyzers.
 *
 * A plugin can provide a specific file analyzer by registering this
 * analyzer component, describing the analyzer.
 */
class Component : public plugin::Component
	{
public:
	using factory_function = Analyzer* (*)(RecordValPtr args, File* file);

	/**
	 * Constructor.
	 *
	 * @param name The name of the provided analyzer. This name is used
	 * across the system to identify the analyzer, e.g., when calling
	 * file_analysis::Manager::InstantiateAnalyzer with a name.
	 *
	 * @param factory A factory function to instantiate instances of the
	 * analyzer's class, which must be derived directly or indirectly
	 * from file_analysis::Analyzer. This is typically a static \c
	 * Instantiate() method inside the class that just allocates and
	 * returns a new instance.
	 *
	 * @param subtype A subtype associated with this component that
	 * further distinguishes it. The subtype will be integrated into the
	 * Tag that the manager associates with this analyzer, and
	 * analyzer instances can accordingly access it via Tag().
	 * If not used, leave at zero.
	 *
	 * @param enabled If false the analyzer starts out as disabled and
	 * hence won't be used. It can still be enabled later via the
	 * manager, including from script-land.
	 */
	Component(const std::string& name, factory_function factory, zeek::Tag::subtype_t subtype = 0,
	          bool enabled = true);

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
	 * Returns the analyzer's factory function.
	 */
	factory_function FactoryFunction() const { return factory_func; }

	/**
	 * Returns true if the analyzer is currently enabled and hence
	 * available for use.
	 */
	bool Enabled() const { return enabled; }

	/**
	 * Enables or disables this analyzer.
	 *
	 * @param arg_enabled True to enabled, false to disable.
	 *
	 */
	void SetEnabled(bool arg_enabled) { enabled = arg_enabled; }

protected:
	/**
	 * Overriden from plugin::Component.
	 */
	void DoDescribe(ODesc* d) const override;

private:
	friend class Manager;

	factory_function factory_func; // The analyzer's factory callback.
	bool enabled; // True if the analyzer is enabled.
	};

	} // namespace file_analysis
	} // namespace zeek
