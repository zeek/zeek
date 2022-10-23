// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <vector>

#include "zeek/plugin/Component.h"

namespace zeek::iosource
	{

class IOSource;
class PktSrc;
class PktDumper;

/**
 * Component description for plugins providing IOSources.
 */
class Component : public plugin::Component
	{
public:
	using factory_callback = IOSource* (*)();

	/**
	 * Constructor.
	 *
	 * @param name A descriptive name for the component.  This name must
	 * be unique across all components of this type.
	 */
	explicit Component(const std::string& name);

	/**
	 * Destructor.
	 */
	~Component() override;

protected:
	/**
	 * Constructor to use by derived classes.
	 *
	 * @param type The type of the component.
	 *
	 * @param name A descriptive name for the component.  This name must
	 * be unique across all components of this type.
	 */
	Component(plugin::component::Type type, const std::string& name);
	};

/**
 * Component description for plugins providing a PktSrc for packet input.
 */
class PktSrcComponent : public Component
	{
public:
	/**
	 * Type of input a packet source supports.
	 */
	enum InputType
		{
		LIVE, ///< Live input.
		TRACE, ///< Offline input from trace file.
		BOTH ///< Live input as well as offline.
		};

	using factory_callback = PktSrc* (*)(const std::string& path, bool is_live);

	/**
	 * Constructor.
	 *
	 * @param name A descriptive name for the component.  This name must
	 * be unique across all components of this type.
	 *
	 * @param prefixes The list of interface/file prefixes associated
	 * with this component.
	 *
	 * @param type Type of input the component supports.
	 *
	 * @param factor Factory function to instantiate component.
	 */
	PktSrcComponent(const std::string& name, const std::string& prefixes, InputType type,
	                factory_callback factory);

	/**
	 * Destructor.
	 */
	~PktSrcComponent() override;

	/**
	 * Returns the prefix(es) passed to the constructor.
	 */
	const std::vector<std::string>& Prefixes() const;

	/**
	 * Returns true if the given prefix is among the one specified for the component.
	 */
	bool HandlesPrefix(const std::string& prefix) const;

	/**
	 * Returns true if packet source instantiated by the component handle
	 * live traffic.
	 */
	bool DoesLive() const;

	/**
	 * Returns true if packet source instantiated by the component handle
	 * offline traces.
	 */
	bool DoesTrace() const;

	/**
	 * Returns the source's factory function.
	 */
	factory_callback Factory() const;

	/**
	 * Generates a human-readable description of the component. This goes
	 * into the output of \c "zeek -NN".
	 */
	void DoDescribe(ODesc* d) const override;

private:
	std::vector<std::string> prefixes;
	InputType type;
	factory_callback factory;
	};

/**
 * Component description for plugins providing a PktDumper for packet output.
 *
 * PktDumpers aren't IOSurces but we locate them here to keep them along with
 * the PktSrc.
 */
class PktDumperComponent : public plugin::Component
	{
public:
	using factory_callback = PktDumper* (*)(const std::string& path, bool append);

	/**
	 * XXX
	 */
	PktDumperComponent(const std::string& name, const std::string& prefixes,
	                   factory_callback factory);

	/**
	 * Destructor.
	 */
	~PktDumperComponent() override;

	/**
	 * Returns the prefix(es) passed to the constructor.
	 */
	const std::vector<std::string>& Prefixes() const;

	/**
	 * Returns true if the given prefix is among the one specified for the component.
	 */
	bool HandlesPrefix(const std::string& prefix) const;

	/**
	 * Returns the source's factory function.
	 */
	factory_callback Factory() const;

	/**
	 * Generates a human-readable description of the component. This goes
	 * into the output of \c "zeek -NN".
	 */
	void DoDescribe(ODesc* d) const override;

private:
	std::vector<std::string> prefixes;
	factory_callback factory;
	};

	} // namespace zeek::iosource
