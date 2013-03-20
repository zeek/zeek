
#ifndef ANALYZER_PLUGIN_COMPONENT_H
#define ANALYZER_PLUGIN_COMPONENT_H

#include <string>

#include "../config.h"
#include "../util.h"

#include "plugin/Component.h"
#include "Tag.h"

class Connection;

namespace analyzer {

class Analyzer;

// This can be copied by value.
class PluginComponent : public plugin::Component {
public:
	typedef bool (*available_callback)();
	typedef Analyzer* (*factory_callback)(Connection* conn);

	PluginComponent(std::string name, factory_callback factory, bool enabled, bool partial);
	PluginComponent(std::string name, Tag::subtype_t subtype, factory_callback factory, bool enabled, bool partial);

	std::string Name() const	{ return name; }
	factory_callback Factory() const	{ return factory; }
	bool Partial() const	{ return partial; }
	bool Enabled() const	{ return enabled; }
	analyzer::Tag Tag() const	{ return tag; }

	void SetEnabled(bool arg_enabled)	{ enabled = arg_enabled; }

	virtual void Describe(ODesc* d);

private:
	std::string name;
	factory_callback factory;
	bool partial;

	analyzer::Tag tag;
	bool enabled;

	static analyzer::Tag::type_t type_counter;
};

}

#endif
