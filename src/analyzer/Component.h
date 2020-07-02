// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Tag.h"
#include "plugin/Component.h"
#include "plugin/TaggedComponent.h"

#include "../zeek-config.h"
#include "../util.h"

class Connection;

ZEEK_FORWARD_DECLARE_NAMESPACED(Analyzer, zeek, analyzer);

namespace zeek::analyzer {

/**
 * Component description for plugins providing analyzers.
 *
 * A plugin can provide a specific protocol analyzer by registering this
 * analyzer component, describing the analyzer.
 */
class Component : public zeek::plugin::Component,
                  public plugin::TaggedComponent<analyzer::Tag> {
public:
	typedef Analyzer* (*factory_callback)(Connection* conn);

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
	 * Instatiate() method inside the class that just allocates and
	 * returns a new instance.
	 *
	 * @param subtype A subtype associated with this component that
	 * further distinguishes it. The subtype will be integrated into
	 * the analyzer::Tag that the manager associates with this analyzer,
	 * and analyzer instances can accordingly access it via analyzer::Tag().
	 * If not used, leave at zero.
	 *
	 * @param enabled If false the analyzer starts out as disabled and
	 * hence won't be used. It can still be enabled later via the
	 * manager, including from script-land.
	 *
	 * @param partial If true, the analyzer can deal with payload from
	 * partial connections, i.e., when Bro enters the stream mid-way
	 * after not seeing the beginning. Note that handling of partial
	 * connections has generally not seen much testing yet as virtually
	 * no existing analyzer supports it.
	 */
	Component(const std::string& name, factory_callback factory, Tag::subtype_t subtype = 0, bool enabled = true, bool partial = false);

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
	factory_callback Factory() const	{ return factory; }

	/**
	 * Returns whether the analyzer supports partial connections. Partial
	 * connections are those where Bro starts processing payload
	 * mid-stream, after missing the beginning.
	 */
	bool Partial() const	{ return partial; }

	/**
	 * Returns true if the analyzer is currently enabled and hence
	 * available for use.
	 */
	bool Enabled() const	{ return enabled; }

	/**
	 * Enables or disables this analyzer.
	 *
	 * @param arg_enabled True to enabled, false to disable.
	 *
	 */
	void SetEnabled(bool arg_enabled)	{ enabled = arg_enabled; }

protected:
	/**
	  * Overriden from plugin::Component.
	  */
	void DoDescribe(ODesc* d) const override;

private:
	factory_callback factory;	// The analyzer's factory callback.
	bool partial;	// True if the analyzer supports partial connections.
	bool enabled;	// True if the analyzer is enabled.
};

} // namespace zeek::analyzer

namespace analyzer {
	using Component [[deprecated("Remove in v4.1. Use zeek::analyzer::Component.")]] = zeek::analyzer::Component;
} // namespace analyzer
