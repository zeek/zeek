// See the file "COPYING" in the main distribution directory for copyright.

#include <cassert>

#include "Plugin.h"
#include "Manager.h"
#include "Component.h"

#include "../Desc.h"

using namespace plugin;

BifItem::BifItem(const std::string& arg_id, Type arg_type)
	{
	id = copy_string(arg_id.c_str());
	type = arg_type;
	}

BifItem::BifItem(const BifItem& other)
	{
	id = copy_string(other.id);
	type = other.type;
	}

BifItem& BifItem::operator=(const BifItem& other)
	{
	if ( this != &other )
		{
		id = copy_string(other.id);
		type = other.type;
		}

	return *this;
	}

BifItem::~BifItem()
	{
	delete [] id;
	}

Plugin::Plugin()
	{
	name = copy_string("<NAME-NOT-SET>");
	description = copy_string("");

	// These will be reset by the BRO_PLUGIN_* macros.
	version = -9999;
	api_version = -9999;
	dynamic = false;

	Manager::RegisterPlugin(this);
	}

Plugin::~Plugin()
	{
	Done();

	delete [] name;
	delete [] description;
	}

const char* Plugin::Name() const
	{
	return name;
	}

void Plugin::SetName(const char* arg_name)
	{
	name = copy_string(arg_name);
	}

const char* Plugin::Description() const
	{
	return description;
	}

void Plugin::SetDescription(const char* arg_description)
	{
	description = copy_string(arg_description);
	}

int Plugin::Version() const
	{
	return dynamic ? version : 0;
	}

void Plugin::SetVersion(int arg_version)
	{
	version = arg_version;
	}

int Plugin::APIVersion() const
	{
	return api_version;
	}

bool Plugin::DynamicPlugin() const
	{
	return dynamic;
	}

void Plugin::SetAPIVersion(int arg_version)
	{
	api_version = arg_version;
	}

void Plugin::SetDynamicPlugin(bool arg_dynamic)
	{
	dynamic = arg_dynamic;
	}

void Plugin::InitPreScript()
	{
	}

void Plugin::InitPostScript()
	{
	for ( bif_init_func_list::const_iterator f = bif_inits.begin(); f != bif_inits.end(); f++ )
		{
		bif_init_func_result items = (**f)();

		for ( bif_init_func_result::const_iterator i = items.begin(); i != items.end(); i++ )
			{
			BifItem bi((*i).first, (BifItem::Type)(*i).second);
			bif_items.push_back(bi);
			}
		}
	}

Plugin::bif_item_list Plugin::BifItems() const
	{
	bif_item_list l1 = bif_items;
	bif_item_list l2 = CustomBifItems();

	for ( bif_item_list::const_iterator i = l2.begin(); i != l2.end(); i++ )
		l1.push_back(*i);

	return l1;
	}

Plugin::bif_item_list Plugin::CustomBifItems() const
	{
	return bif_item_list();
	}

void Plugin::Done()
	{
	for ( component_list::const_iterator i = components.begin(); i != components.end(); i++ )
		delete *i;

	components.clear();
	}

Plugin::component_list Plugin::Components() const
	{
	return components;
	}

static bool component_cmp(const Component* a, const Component* b)
	{
	return a->Name() < b->Name();
	}

void Plugin::AddComponent(Component* c)
	{
	components.push_back(c);

	// Sort components by name to make sure we have a deterministic
	// order.
	components.sort(component_cmp);
	}

void Plugin::AddBifInitFunction(bif_init_func c)
	{
	bif_inits.push_back(c);
	}

void Plugin::Describe(ODesc* d) const
	{
	d->Add("Plugin: ");
	d->Add(name);

	if ( description && *description )
		{
		d->Add(" - ");
		d->Add(description);
		}

	if ( dynamic )
		{
		if ( version > 0 )
			{
			d->Add(" (version ");
			d->Add(version);
			d->Add(")");
			}
		else
			d->Add(" (version not set)");
		}

	else
		d->Add(" (built-in)");

	d->Add("\n");

	if ( d->IsShort() )
		return;

	for ( component_list::const_iterator i = components.begin(); i != components.end(); i++ )
		{
		(*i)->Describe(d);
		d->Add("\n");
		}

	bif_item_list items = BifItems();

	for ( bif_item_list::const_iterator i = items.begin(); i != items.end(); i++ )
		{
		const char* type = 0;

		switch ( (*i).GetType() ) {
		case BifItem::FUNCTION:
			type = "Function";
			break;

		case BifItem::EVENT:
			type = "Event";
			break;

		case BifItem::CONSTANT:
			type = "Constant";
			break;

		case BifItem::GLOBAL:
			type = "Global";
			break;

		case BifItem::TYPE:
			type = "Type";
			break;

		default:
			type = "<unknown>";
		}

		d->Add("    ");
		d->Add("[");
		d->Add(type);
		d->Add("] ");
		d->Add((*i).GetID());
		d->Add("\n");
		}
	}


