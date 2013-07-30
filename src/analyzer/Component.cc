// See the file "COPYING" in the main distribution directory for copyright.

#include "Component.h"
#include "Manager.h"

#include "../Desc.h"
#include "../util.h"

using namespace analyzer;

analyzer::Tag::type_t Component::type_counter = 0;

Component::Component(const char* arg_name, factory_callback arg_factory, Tag::subtype_t arg_subtype, bool arg_enabled, bool arg_partial)
	: plugin::Component(plugin::component::ANALYZER)
	{
	name = copy_string(arg_name);
	canon_name = canonify_name(arg_name);
	factory = arg_factory;
	enabled = arg_enabled;
	partial = arg_partial;

	tag = analyzer::Tag(++type_counter, arg_subtype);
	}

Component::Component(const Component& other)
	: plugin::Component(Type())
	{
	name = copy_string(other.name);
	canon_name = copy_string(other.canon_name);
	factory = other.factory;
	enabled = other.enabled;
	partial = other.partial;
	tag = other.tag;
	}

Component::~Component()
	{
	delete [] name;
	delete [] canon_name;
	}

analyzer::Tag Component::Tag() const
	{
	return tag;
	}

void Component::Describe(ODesc* d) const
	{
	plugin::Component::Describe(d);
	d->Add(name);
	d->Add(" (");

	if ( factory )
		{
		d->Add("ANALYZER_");
		d->Add(canon_name);
		d->Add(", ");
		}

	d->Add(enabled ? "enabled" : "disabled");
	d->Add(")");
	}

Component& Component::operator=(const Component& other)
	{
	if ( &other != this )
		{
		name = copy_string(other.name);
		factory = other.factory;
		enabled = other.enabled;
		partial = other.partial;
		tag = other.tag;
		}

	return *this;
	}
