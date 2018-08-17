
#include "Plugin.h"

#include <Func.h>
#include <Event.h>
#include <Conn.h>
#include <threading/Formatter.h>

namespace plugin { namespace Demo_Hooks { Plugin plugin; } }

using namespace plugin::Demo_Hooks;

plugin::Configuration Plugin::Configure()
	{
	EnableHook(HOOK_LOAD_FILE);
	EnableHook(HOOK_CALL_FUNCTION);
	EnableHook(HOOK_QUEUE_EVENT);
	EnableHook(HOOK_DRAIN_EVENTS);
	EnableHook(HOOK_UPDATE_NETWORK_TIME);
	EnableHook(META_HOOK_PRE);
	EnableHook(META_HOOK_POST);
	EnableHook(HOOK_BRO_OBJ_DTOR);
	EnableHook(HOOK_SETUP_ANALYZER_TREE);
	EnableHook(HOOK_LOG_INIT);
	EnableHook(HOOK_LOG_WRITE);

	plugin::Configuration config;
	config.name = "Demo::Hooks";
	config.description = "Exercises all plugin hooks";
	config.version.major = 1;
	config.version.minor = 0;
	return config;
	}

static void describe_hook_args(const plugin::HookArgumentList& args, ODesc* d)
	{
	bool first = true;

	for ( plugin::HookArgumentList::const_iterator i = args.begin(); i != args.end(); i++ )
		{
		if ( ! first )
			d->Add(", ");

		i->Describe(d);
		first = false;
		}
	}

int Plugin::HookLoadFile(const LoadType type, const std::string& file, const std::string& resolved)
	{
	fprintf(stderr, "%.6f %-15s %s %s\n", network_time, "| HookLoadFile",
		file.c_str(), resolved.c_str());
	return -1;
	}

std::pair<bool, Val*> Plugin::HookCallFunction(const Func* func, Frame* frame, val_list* args)
	{
	ODesc d;
	d.SetShort();
	HookArgument(func).Describe(&d);
	HookArgument(args).Describe(&d);
	fprintf(stderr, "%.6f %-15s %s\n", network_time, "| HookCallFunction",
		d.Description());

	return std::pair<bool, Val*>(false, NULL);
	}

bool Plugin::HookQueueEvent(Event* event)
	{
	ODesc d;
	d.SetShort();
	HookArgument(event).Describe(&d);
	fprintf(stderr, "%.6f %-15s %s\n", network_time, "| HookQueueEvent",
		d.Description());

	static int i = 0;

	if ( network_time && i == 0 )
		{
		fprintf(stderr, "%.6f %-15s %s\n", network_time, "| RequestObjDtor",
			d.Description());

		RequestBroObjDtor(event);
		i = 1;
		}

	return false;
	}

void Plugin::HookDrainEvents()
	{
	fprintf(stderr, "%.6f %-15s\n", network_time, "| HookDrainEvents");
	}

void Plugin::HookUpdateNetworkTime(double network_time)
	{
	fprintf(stderr, "%.6f  %-15s %.6f\n", ::network_time, "| HookUpdateNetworkTime",
		network_time);
	}

void Plugin::HookBroObjDtor(void* obj)
	{
	fprintf(stderr, "%.6f  %-15s\n", ::network_time, "| HookBroObjDtor");
	}

void Plugin::MetaHookPre(HookType hook, const HookArgumentList& args)
	{
	ODesc d;
	d.SetShort();
	describe_hook_args(args, &d);
	fprintf(stderr, "%.6f %-15s %s(%s)\n", network_time, "  MetaHookPre",
		hook_name(hook), d.Description());
	}

void Plugin::MetaHookPost(HookType hook, const HookArgumentList& args, HookArgument result)
	{
	ODesc d1;
	d1.SetShort();
	describe_hook_args(args, &d1);

	ODesc d2;
	d2.SetShort();
	result.Describe(&d2);

	fprintf(stderr, "%.6f %-15s %s(%s) -> %s\n", network_time, "  MetaHookPost",
		hook_name(hook), d1.Description(),
		d2.Description());
	}

void Plugin::HookSetupAnalyzerTree(Connection *conn)
	{
	ODesc d;
	d.SetShort();
	conn->Describe(&d);

	fprintf(stderr, "%.6f %-15s %s\n", network_time, "| HookSetupAnalyzerTree", d.Description());
	}

void Plugin::HookLogInit(const std::string& writer, const std::string& instantiating_filter, bool local, bool remote, const logging::WriterBackend::WriterInfo& info, int num_fields, const threading::Field* const* fields)
	{
	ODesc d;

	d.Add("{");
	for ( int i=0; i < num_fields; i++ )
		{
		const threading::Field* f = fields[i];

		if ( i > 0 )
			d.Add(", ");

		d.Add(f->name);
		d.Add(" (");
		d.Add(f->TypeName());
		d.Add(")");
		}
	d.Add("}");

	fprintf(stderr, "%.6f %-15s %s %d/%d %s\n", network_time, "| HookLogInit", info.path, local, remote, d.Description());
	}

void Plugin::RenderVal(const threading::Value* val, ODesc &d) const
	{
		if ( ! val->present )
			{
			d.Add("<uninitialized>");
			return;
			}

		switch ( val->type ) {

			case TYPE_BOOL:
				d.Add(val->val.int_val ? "T" : "F");
				break;

			case TYPE_INT:
				d.Add(val->val.int_val);
				break;

			case TYPE_COUNT:
			case TYPE_COUNTER:
				d.Add(val->val.uint_val);
				break;

			case TYPE_PORT:
				d.Add(val->val.port_val.port);
				break;

			case TYPE_SUBNET:
				d.Add(threading::formatter::Formatter::Render(val->val.subnet_val));
				break;

			case TYPE_ADDR:
				d.Add(threading::formatter::Formatter::Render(val->val.addr_val));
				break;

			case TYPE_DOUBLE:
				d.Add(val->val.double_val, true);
				break;

			case TYPE_INTERVAL:
			case TYPE_TIME:
				d.Add(threading::formatter::Formatter::Render(val->val.double_val));
				break;

			case TYPE_ENUM:
			case TYPE_STRING:
			case TYPE_FILE:
			case TYPE_FUNC:
				d.AddN(val->val.string_val.data, val->val.string_val.length);
				break;

			case TYPE_TABLE:
				for ( int j = 0; j < val->val.set_val.size; j++ )
					{
					if ( j > 0 )
						d.Add(",");

					RenderVal(val->val.set_val.vals[j], d);
					}
				break;

			case TYPE_VECTOR:
				for ( int j = 0; j < val->val.vector_val.size; j++ )
					{
					if ( j > 0 )
						d.Add(",");

					RenderVal(val->val.vector_val.vals[j], d);
					}
				break;

			default:
				assert(false);
		}
	}

bool Plugin::HookLogWrite(const std::string& writer, const std::string& filter, const logging::WriterBackend::WriterInfo& info, int num_fields, const threading::Field* const* fields, threading::Value** vals)
	{
	ODesc d;

	d.Add("[");
	for ( int i=0; i < num_fields; i++ )
		{
		const threading::Field* f = fields[i];
		const threading::Value* val = vals[i];

		if ( i > 0 )
			d.Add(", ");

		d.Add(f->name);
		d.Add("=");

		RenderVal(val, d);
		}
	d.Add("]");

	fprintf(stderr, "%.6f %-15s %s %s\n", network_time, "| HookLogWrite", info.path, d.Description());
	return true;
	}
