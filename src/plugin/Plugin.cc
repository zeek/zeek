// See the file  in the main distribution directory for copyright.

// See the file "COPYING" in the main distribution directory for copyright.

#include <cassert>

#include "Plugin.h"
#include "Manager.h"
#include "Component.h"

#include "../Desc.h"
#include "../Event.h"

using namespace plugin;

const char* plugin::hook_name(HookType h)
{
	static const char* hook_names[int(NUM_HOOKS) + 1] = {
		// Order must match that of HookType.
		"LoadFile",
		"CallFunction",
		"QueueEvent",
		"DrainEvents",
		"UpdateNetworkTime",
		"BroObjDtor",
		"SetupAnalyzerTree",
		// MetaHooks
		"MetaHookPre",
		"MetaHookPost",
		// End marker.
		"<end>",
	};

	return hook_names[int(h)];
	}

BifItem::BifItem(const std::string& arg_id, Type arg_type)
	{
	id = arg_id;
	type = arg_type;
	}

BifItem::BifItem(const BifItem& other)
	{
	id = other.id;
	type = other.type;
	}

BifItem& BifItem::operator=(const BifItem& other)
	{
	if ( this != &other )
		{
		id = other.id;
		type = other.type;
		}

	return *this;
	}

BifItem::~BifItem()
	{
	}

void HookArgument::Describe(ODesc* d) const
	{
	switch ( type ) {
	case BOOL:
		d->Add(arg.bool_ ? "true" : "false");
		break;

	case DOUBLE:
		d->Add(arg.double_);
		break;

	case EVENT:
		if ( arg.event )
			{
			d->Add(arg.event->Handler()->Name());
			d->Add("(");
			describe_vals(arg.event->Args(), d);
			d->Add(")");
			}
		else
			d->Add("<null>");
		break;

	case FUNC_RESULT:
		if ( func_result.first )
			{
			if( func_result.second )
				func_result.second->Describe(d);
			else
				d->Add("<null>");
			}
		else
			d->Add("<no result>");

		break;

	case FRAME:
		if ( arg.frame )
			d->Add("<frame>");
		else
			d->Add("<null>");
		break;

	case FUNC:
		if ( arg.func )
			d->Add(arg.func->Name());
		else
			d->Add("<null>");
		break;

	case INT:
		d->Add(arg.int_);
		break;

	case STRING:
		d->Add(arg_string);
		break;

	case VAL:
		if ( arg.val )
			arg.val->Describe(d);

		else
			d->Add("<null>");
		break;

	case VAL_LIST:
		if ( arg.vals )
			{
			d->Add("(");
			describe_vals(arg.vals, d);
			d->Add(")");
			}
		else
			d->Add("<null>");
		break;

	case VOID:
		d->Add("<void>");
		break;

	case VOIDP:
		d->Add("<void ptr>");
		break;
	}
	}

Plugin::Plugin()
	{
	dynamic = false;
	Manager::RegisterPlugin(this);
	}

Plugin::~Plugin()
	{
	Done();
	}

void Plugin::DoConfigure()
	{
	config = Configure();
	}

const std::string& Plugin::Name() const
	{
	return config.name;
	}

const std::string& Plugin::Description() const
	{
	return config.description;
	}

VersionNumber Plugin::Version() const
	{
	return config.version;
	}

int Plugin::APIVersion() const
	{
	return config.api_version;
	}

bool Plugin::DynamicPlugin() const
	{
	return dynamic;
	}

const std::string& Plugin::PluginDirectory() const
	{
	return base_dir;
	}

const std::string& Plugin::PluginPath() const
	{
	return sopath;
	}

void Plugin::SetPluginLocation(const std::string& arg_dir, const std::string& arg_sopath)
	{
	base_dir = arg_dir;
	sopath = arg_sopath;
	}

void Plugin::SetDynamic(bool is_dynamic)
	{
	dynamic = is_dynamic;
	}

void Plugin::InitPreScript()
	{
	}

void Plugin::InitPostScript()
	{
	}

Plugin::bif_item_list Plugin::BifItems() const
	{
	return bif_items;
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

bool Plugin::LoadBroFile(const std::string& file)
	{
	::add_input_file(file.c_str());
	return true;
	}

void Plugin::AddBifItem(const std::string& name, BifItem::Type type)
	{
	BifItem bi(name, (BifItem::Type)type);
	bif_items.push_back(bi);
	}

void Plugin::AddComponent(Component* c)
	{
	components.push_back(c);

	// Sort components by name to make sure we have a deterministic
	// order.
	components.sort(component_cmp);
	}

Plugin::hook_list Plugin::EnabledHooks() const
	{
	return plugin_mgr->HooksEnabledForPlugin(this);
	}

void Plugin::EnableHook(HookType hook, int priority)
	{
	plugin_mgr->EnableHook(hook, this, priority);
	}

void Plugin::DisableHook(HookType hook)
	{
	plugin_mgr->DisableHook(hook, this);
	}

void Plugin::RequestEvent(EventHandlerPtr handler)
	{
	plugin_mgr->RequestEvent(handler, this);
	}

void Plugin::RequestBroObjDtor(BroObj* obj)
	{
	plugin_mgr->RequestBroObjDtor(obj, this);
	}

int Plugin::HookLoadFile(const std::string& file, const std::string& ext)
	{
	return -1;
	}

std::pair<bool, Val*> Plugin::HookCallFunction(const Func* func, Frame *parent, val_list* args)
	{
	std::pair<bool, Val*> result(false, NULL);
	return result;
	}

bool Plugin::HookQueueEvent(Event* event)
	{
	return false;
	}

void Plugin::HookDrainEvents()
	{
	}

void Plugin::HookUpdateNetworkTime(double network_time)
	{
	}

void Plugin::HookSetupAnalyzerTree(Connection *conn)
	{
	}

void Plugin::HookBroObjDtor(void* obj)
	{
	}

void Plugin::MetaHookPre(HookType hook, const HookArgumentList& args)
	{
	}

void Plugin::MetaHookPost(HookType hook, const HookArgumentList& args, HookArgument result)
	{
	}

void Plugin::Describe(ODesc* d) const
	{
	d->Add(config.name);

	if ( config.description.size() )
		{
		d->Add(" - ");
		d->Add(config.description);
		}

	if ( dynamic )
		{
		d->Add(" (dynamic, ");

		if ( config.version )
			{
			d->Add("version ");
			d->Add(config.version.major);
			d->Add(".");
			d->Add(config.version.minor);
			d->Add(")");
			}
		else
			d->Add("no version information)");
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

	hook_list hooks = EnabledHooks();

	for ( hook_list::iterator i = hooks.begin(); i != hooks.end(); i++ )
		{
		HookType hook = (*i).first;
		int prio = (*i).second;

		d->Add("    Implements ");
		d->Add(hook_name(hook));
		d->Add(" (priority ");
		d->Add(prio);
		d->Add(")\n");
		}
	}

