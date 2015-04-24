// See the file "COPYING" in the main distribution directory for copyright.

#include "Component.h"
#include "Manager.h"

#include "../Desc.h"
#include "../util.h"

using namespace analyzer;

Component::Component(const std::string& name, factory_callback arg_factory, Tag::subtype_t arg_subtype, bool arg_enabled, bool arg_partial)
	: plugin::Component(plugin::component::ANALYZER, name),
	  plugin::TaggedComponent<analyzer::Tag>(arg_subtype)
	{
	factory = arg_factory;
	enabled = arg_enabled;
	partial = arg_partial;

	analyzer_mgr->RegisterComponent(this, "ANALYZER_");
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
		d->Add(", ");
		}

	d->Add(enabled ? "enabled" : "disabled");
	}
