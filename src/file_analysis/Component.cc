// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/file_analysis/Component.h"

#include "zeek/Desc.h"
#include "zeek/util.h"
#include "zeek/file_analysis/Manager.h"

namespace zeek::file_analysis {

Component::Component(const std::string& name, factory_callback arg_factory, Tag::subtype_t subtype)
	: plugin::Component(plugin::component::FILE_ANALYZER, name),
	  plugin::TaggedComponent<file_analysis::Tag>(subtype)
	{
	factory = arg_factory;
	factory_func = nullptr;
	}

Component::Component(const std::string& name, factory_function arg_factory, Tag::subtype_t subtype)
	: plugin::Component(plugin::component::FILE_ANALYZER, name),
	  plugin::TaggedComponent<file_analysis::Tag>(subtype)
	{
	factory = nullptr;
	factory_func = arg_factory;
	}

void Component::Initialize()
	{
	InitializeTag();
	file_mgr->RegisterComponent(this, "ANALYZER_");
	}

Component::~Component()
	{
	}

void Component::DoDescribe(ODesc* d) const
	{
	if ( factory || factory_func )
		{
		d->Add("ANALYZER_");
		d->Add(CanonicalName());
		}
	}

} // namespace zeek::file_analysis
