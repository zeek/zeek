
#include "PluginComponent.h"

#include "../Desc.h"

using namespace analyzer;

Tag::type_t PluginComponent::type_counter = 0;

PluginComponent::PluginComponent(std::string arg_name, factory_callback arg_factory, bool arg_enabled, bool arg_partial)
	: Component(plugin::component::ANALYZER)
	{
	name = arg_name;
	factory = arg_factory;
	enabled = arg_enabled;
	partial = arg_partial;

	tag = analyzer::Tag(++type_counter, 0);
	}

PluginComponent::PluginComponent(std::string arg_name, Tag::subtype_t arg_stype, factory_callback arg_factory, bool arg_enabled, bool arg_partial)
	: Component(plugin::component::ANALYZER)
	{
	name = arg_name;
	factory = arg_factory;
	enabled = arg_enabled;
	partial = arg_partial;

	tag = analyzer::Tag(++type_counter, arg_stype);
	}

void PluginComponent::Describe(ODesc* d)
	{
	plugin::Component::Describe(d);
	d->Add(name);
	}

