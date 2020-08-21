// See the file "COPYING" in the main distribution directory for copyright.

#include "Component.h"
#include "Manager.h"

#include "../Desc.h"
#include "../util.h"

namespace zeek::file_analysis {

Component::Component(const std::string& name, factory_callback arg_factory, Tag::subtype_t subtype)
	: zeek::plugin::Component(zeek::plugin::component::FILE_ANALYZER, name),
	  zeek::plugin::TaggedComponent<zeek::file_analysis::Tag>(subtype)
	{
	factory = arg_factory;
	factory_func = nullptr;
	}

Component::Component(const std::string& name, factory_function arg_factory, Tag::subtype_t subtype)
	: zeek::plugin::Component(zeek::plugin::component::FILE_ANALYZER, name),
	  zeek::plugin::TaggedComponent<zeek::file_analysis::Tag>(subtype)
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

void Component::DoDescribe(zeek::ODesc* d) const
	{
	if ( factory )
		{
		d->Add("ANALYZER_");
		d->Add(CanonicalName());
		}
	}

} // namespace zeek::file_analysis
