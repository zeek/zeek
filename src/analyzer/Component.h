// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"

#include "zeek/Tag.h"
#include "zeek/plugin/Component.h"
#include "zeek/util.h"

namespace zeek
	{

class Connection;

namespace analyzer
	{

class Analyzer;

/**
 * Component description for plugins providing analyzers.
 *
 * A plugin can provide a specific protocol analyzer by registering this
 * analyzer component, describing the analyzer.
 */
class Component : public plugin::Component
	{
public:
	using factory_callback = Analyzer* (*)(Connection* conn);

	/**
	 * Constructor.
	 *
	 * @param name The name of the provided analyzer. This name is used
	 * across the system to identify the analyzer, e.g., when calling
	 * analyzer::Manager::InstantiateAnalyzer with a name.
	 *
	 * @param factory A factory function to instantiate instances of the
	 * analyzer's class, which must be derived directly or indirectly
	 * from zeek::analyzer::Analyzer. This is typically a static \c
	 * Instantiate() method inside the class that just allocates and
	 * returns a new instance.
	 *
	 * @param subtype A subtype associated with this component that
	 * further distinguishes it. The subtype will be integrated into
	 * the Tag that the manager associates with this analyzer,
	 * and analyzer instances can accordingly access it via Tag().
	 * If not used, leave at zero.
	 *
	 * @param enabled If false the analyzer starts out as disabled and
	 * hence won't be used. It can still be enabled later via the
	 * manager, including from script-land.
	 *
	 * @param partial If true, the analyzer can deal with payload from
	 * partial connections, i.e., when Zeek enters the stream mid-way
	 * after not seeing the beginning. Note that handling of partial
	 * connections has generally not seen much testing yet as virtually
	 * no existing analyzer supports it.
	 *
	 * @param adapter If true, this analyzer is a session adapter from
	 * the packet analyzer framework.
	 */
	Component(const std::string& name, factory_callback factory, zeek::Tag::subtype_t subtype = 0,
	          bool enabled = true, bool partial = false, bool adapter = false);

	/**
	 * Destructor.
	 */
	~Component() override = default;

	/**
	 * Initialization function. This function has to be called before any
	 * plugin component functionality is used; it is used to add the
	 * plugin component to the list of components and to initialize tags
	 */
	void Initialize() override;

	/**
	 * Returns the analyzer's factory function.
	 */
	factory_callback Factory() const { return factory; }

	/**
	 * Returns whether the analyzer supports partial connections. Partial
	 * connections are those where Zeek starts processing payload
	 * mid-stream, after missing the beginning.
	 */
	bool Partial() const { return partial; }

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
	factory_callback factory; // The analyzer's factory callback.
	bool partial; // True if the analyzer supports partial connections.
	bool enabled; // True if the analyzer is enabled.
	};

	} // namespace analyzer
	} // namespace zeek
