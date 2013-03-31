
#include "Component.h"

#include "../Desc.h"

using namespace analyzer;

Tag::type_t Component::type_counter = 0;

Component::Component(std::string arg_name, factory_callback arg_factory, Tag::subtype_t arg_subtype, bool arg_enabled, bool arg_partial)
	: plugin::Component(plugin::component::ANALYZER)
	{
	name = arg_name;
	factory = arg_factory;
	enabled = arg_enabled;
	partial = arg_partial;

	tag = analyzer::Tag(++type_counter, arg_subtype);
	}

void Component::Describe(ODesc* d)
	{
	plugin::Component::Describe(d);
	d->Add(name);
	d->Add(" (");
	d->Add(enabled ? "enabled" : "disabled");
	d->Add(")");
	}

