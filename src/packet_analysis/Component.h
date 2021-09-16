// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <functional>

#include "zeek/packet_analysis/Tag.h"
#include "zeek/plugin/Component.h"
#include "zeek/plugin/TaggedComponent.h"
#include "zeek/util.h"
#include "zeek/zeek-config.h"

namespace zeek::packet_analysis
	{

class Analyzer;
using AnalyzerPtr = std::shared_ptr<Analyzer>;

class Component : public plugin::Component, public plugin::TaggedComponent<packet_analysis::Tag>
	{
public:
	using factory_callback = std::function<AnalyzerPtr()>;

	Component(const std::string& name, factory_callback factory, Tag::subtype_t subtype = 0);
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

protected:
	/**
	 * Overriden from plugin::Component.
	 */
	void DoDescribe(ODesc* d) const override;

private:
	factory_callback factory; // The analyzer's factory callback.
	};

	}
