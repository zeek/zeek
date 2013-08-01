// See the file "COPYING" in the main distribution directory for copyright.

#include "Component.h"
#include "Manager.h"

#include "../Desc.h"
#include "../util.h"

using namespace file_analysis;

Component::Component(const char* arg_name, factory_callback arg_factory)
	: plugin::Component(plugin::component::FILE_ANALYZER),
	  plugin::TaggedComponent<file_analysis::Tag>()
	{
	name = copy_string(arg_name);
	canon_name = canonify_name(arg_name);
	factory = arg_factory;
	}

Component::Component(const Component& other)
	: plugin::Component(Type()),
	  plugin::TaggedComponent<file_analysis::Tag>(other)
	{
	name = copy_string(other.name);
	canon_name = copy_string(other.canon_name);
	factory = other.factory;
	}

Component::~Component()
	{
	delete [] name;
	delete [] canon_name;
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
		}

	d->Add(")");
	}

Component& Component::operator=(const Component& other)
	{
	plugin::TaggedComponent<file_analysis::Tag>::operator=(other);

	if ( &other != this )
		{
		name = copy_string(other.name);
		factory = other.factory;
		}

	return *this;
	}
