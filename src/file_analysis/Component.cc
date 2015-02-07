// See the file "COPYING" in the main distribution directory for copyright.

#include "Component.h"
#include "Manager.h"

#include "../Desc.h"
#include "../util.h"

using namespace file_analysis;

Component::Component(const std::string& name, factory_callback arg_factory, Tag::subtype_t subtype)
	: plugin::Component(plugin::component::FILE_ANALYZER, name),
	  plugin::TaggedComponent<file_analysis::Tag>(subtype)
	{
	factory = arg_factory;

	file_mgr->RegisterComponent(this, "ANALYZER_");
	}

Component::~Component()
	{
	}

void Component::DoDescribe(ODesc* d) const
	{
	if ( factory )
		{
		d->Add("ANALYZER_");
		d->Add(CanonicalName());
		}
	}
