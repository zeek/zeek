// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/Component.h"

#include "zeek/Desc.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/util.h"

namespace zeek::analyzer
	{

Component::Component(const std::string& name, factory_callback arg_factory,
                     zeek::Tag::subtype_t arg_subtype, bool arg_enabled, bool arg_partial,
                     bool arg_adapter)
	: plugin::Component(arg_adapter ? plugin::component::SESSION_ADAPTER
                                    : plugin::component::ANALYZER,
                        name, arg_subtype, analyzer_mgr->GetTagType())
	{
	factory = arg_factory;
	enabled = arg_enabled;
	partial = arg_partial;
	}

void Component::Initialize()
	{
	InitializeTag();
	analyzer_mgr->RegisterComponent(this, "ANALYZER_");
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

	} // namespace zeek::analyzer
