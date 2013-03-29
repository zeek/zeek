
#include <cassert>

#include "Plugin.h"
#include "Manager.h"
#include "Component.h"

#include "../Desc.h"

using namespace plugin;

Description::Description()
	{
	name = "<NAME-NOT-SET>";

	// These will be reset by the BRO_PLUGIN_* macros.
	version = -9999;
	api_version = -9999;
	}

Plugin::Plugin()
	{
	Manager::RegisterPlugin(this);
	}

Description Plugin::GetDescription() const
	{
	return description;
	}

void Plugin::SetDescription(Description& desc)
	{
	description = desc;
	}

Plugin::~Plugin()
	{
	Done();
	}

void Plugin::Init()
	{
	}

void Plugin::InitBif()
	{
	for ( bif_init_func_list::const_iterator f = bif_inits.begin(); f != bif_inits.end(); f++ )
		{
		bif_init_func_result items = (**f)();

		for ( bif_init_func_result::const_iterator i = items.begin(); i != items.end(); i++ )
			{
			BifItem bi;
			bi.id = (*i).first;
			bi.type = (BifItem::Type)(*i).second;
			bif_items.push_back(bi);
			}
		}
	}

const Plugin::bif_item_list& Plugin::BifItems()
	{
	return bif_items;
	}

void Plugin::Done()
	{
	for ( component_list::const_iterator i = components.begin(); i != components.end(); i++ )
		delete *i;

	components.clear();
	}

Plugin::component_list Plugin::Components()
	{
	return components;
	}

void Plugin::AddComponent(Component* c)
	{
	components.push_back(c);
	}

void Plugin::AddBifInitFunction(bif_init_func c)
	{
	bif_inits.push_back(c);
	}

void Plugin::Describe(ODesc* d)
	{
	d->Add("Plugin: ");
	d->Add(description.name);

	if ( description.description.size() )
		{
		d->Add(" - ");
		d->Add(description.description);
		}

	if ( description.version != BRO_PLUGIN_VERSION_BUILTIN )
		{
		d->Add(" (version ");
		d->Add(description.version);

		if ( description.url.size() )
			{
			d->Add(", from ");
			d->Add(description.url);
			}

		d->Add(")");
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

	for ( bif_item_list::const_iterator i = bif_items.begin(); i != bif_items.end(); i++ )
		{
		const char* type = 0;

		switch ( (*i).type ) {
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
		d->Add((*i).id);
		d->Add("\n");
		}
	}


