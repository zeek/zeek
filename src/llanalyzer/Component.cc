// See the file "COPYING" in the main distribution directory for copyright.

#include "Component.h"
#include "Desc.h"
#include "Manager.h"

using namespace zeek::llanalyzer;

Component::Component(const std::string& name, factory_callback arg_factory, Tag::subtype_t arg_subtype, bool arg_enabled)
	: plugin::Component(plugin::component::LLANALYZER, name),
	  plugin::TaggedComponent<llanalyzer::Tag>(arg_subtype)
	{
	factory = arg_factory;
	enabled = arg_enabled;
	}

void Component::Initialize()
	{
	InitializeTag();
	llanalyzer_mgr->RegisterComponent(this, "LLANALYZER_");
	}

void Component::DoDescribe(ODesc* d) const
	{
	if ( factory )
		{
		d->Add("LLANALYZER_");
		d->Add(CanonicalName());
		d->Add(", ");
		}

	d->Add(enabled ? "enabled" : "disabled");
	}
