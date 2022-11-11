// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"

#include <string>

#include "zeek/Tag.h"
#include "zeek/Type.h"
#include "zeek/Val.h"

namespace zeek
	{

class ODesc;

namespace plugin
	{
namespace component
	{

/**
 * Component types.
 */
enum Type
	{
	READER, /// An input reader (not currently used).
	WRITER, /// A logging writer (not currently used).
	ANALYZER, /// A protocol analyzer.
	PACKET_ANALYZER, /// A packet analyzer.
	FILE_ANALYZER, /// A file analyzer.
	IOSOURCE, /// An I/O source, excluding packet sources.
	PKTSRC, /// A packet source.
	PKTDUMPER, /// A packet dumper.
	SESSION_ADAPTER, /// A session adapter analyzer.
	};

	} // namespace component

/**
 * Base class for plugin components. A component is a specific piece of
 * functionality that a plugin provides, such as a protocol analyzer or a log
 * writer.
 */
class Component
	{
public:
	/**
	 * Constructor.
	 *
	 * @param type The type of the component.
	 *
	 * @param name A descriptive name for the component.  This name must
	 * be unique across all components of the same type.
	 *
	 * @param tag_subtype A subtype associated with this component that
	 * further distinguishes it. The subtype will be integrated into
	 * the Tag that the manager associates with this component,
	 * and component instances can accordingly access it via Tag().
	 * If not used, leave at zero.
	 *
	 * @param etype An enum type that describes the type for the tag in
	 * script-land.
	 */
	Component(component::Type type, const std::string& name, Tag::subtype_t tag_subtype = 0,
	          EnumTypePtr etype = nullptr);

	/**
	 * Destructor.
	 */
	virtual ~Component() = default;

	// Disable.
	Component(const Component& other) = delete;
	Component operator=(const Component& other) = delete;

	/**
	 * Initialization function. This function has to be called before any
	 * plugin component functionality is used; it commonly is used to add the
	 * plugin component to the list of components and to initialize tags
	 */
	virtual void Initialize() { }

	/**
	 * Returns the component's type.
	 */
	component::Type Type() const { return type; }

	/**
	 * Returns the component's name.
	 */
	const std::string& Name() const { return name; }

	/**
	 * Returns a canonicalized version of the components's name.  The
	 * returned name is derived from what's passed to the constructor but
	 * upper-cased and transformed to allow being part of a script-level
	 * ID.
	 */
	const std::string& CanonicalName() const { return canon_name; }
	StringValPtr CanonicalNameVal() const { return canon_name_val; }

	/**
	 * Returns a textual representation of the component. This goes into
	 * the output of "zeek -NN".
	 *
	 * By default, this just outputs the type and the name. Derived
	 * versions can override DoDescribe() to add type specific details.
	 *
	 * @param d The description object to use.
	 */
	void Describe(ODesc* d) const;

	/**
	 * Initializes tag by creating the unique tag value for this component.
	 * Has to be called exactly once.
	 */
	void InitializeTag();

	/**
	 * @return The component's tag.
	 */
	zeek::Tag Tag() const;

protected:
	/**
	 * Adds type specific information to the output of Describe().
	 *
	 * The default version does nothing.
	 *
	 * @param d The description object to use.
	 */
	virtual void DoDescribe(ODesc* d) const { }

private:
	component::Type type;
	std::string name;
	std::string canon_name;
	StringValPtr canon_name_val;

	/** The automatically assigned component tag */
	zeek::Tag tag;
	EnumTypePtr etype;
	Tag::subtype_t tag_subtype;
	bool tag_initialized = false;

	/** Used to generate globally unique tags */
	static Tag::type_t type_counter;
	};

	} // namespace plugin
	} // namespace zeek
