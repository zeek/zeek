#include "EventHandler.h"
#include "Event.h"
#include "Desc.h"
#include "Func.h"
#include "Scope.h"
#include "NetVar.h"
#include "ID.h"

#include "broker/Manager.h"
#include "broker/Data.h"

EventHandler::EventHandler(const char* arg_name)
	{
	name = copy_string(arg_name);
	used = false;
	local = nullptr;
	type = nullptr;
	error_handler = false;
	enabled = true;
	generate_always = false;
	}

EventHandler::~EventHandler()
	{
	Unref(local);
	delete [] name;
	}

EventHandler::operator bool() const
	{
	return enabled && ((local && local->HasBodies())
			   || generate_always
			   || ! auto_publish.empty());
	}

FuncType* EventHandler::FType(bool check_export)
	{
	if ( type )
		return type;

	auto id = lookup_ID(name, current_module.c_str(), false, false,
	                    check_export);

	if ( ! id )
		return nullptr;

	if ( id->GetType()->Tag() != TYPE_FUNC )
		return nullptr;

	type = id->GetType()->AsFuncType();
	return type;
	}

void EventHandler::SetLocalHandler(Func* f)
	{
	if ( local )
		Unref(local);

	Ref(f);
	local = f;
	}

void EventHandler::Call(const zeek::Args& vl, bool no_remote)
	{
#ifdef PROFILE_BRO_FUNCTIONS
	DEBUG_MSG("Event: %s\n", Name());
#endif

	if ( new_event )
		NewEvent(vl);

	if ( ! no_remote )
		{
		if ( ! auto_publish.empty() )
			{
			// Send event in form [name, xs...] where xs represent the arguments.
			broker::vector xs;
			xs.reserve(vl.size());
			bool valid_args = true;

			for ( auto i = 0u; i < vl.size(); ++i )
				{
				auto opt_data = bro_broker::val_to_data(vl[i].get());

				if ( opt_data )
					xs.emplace_back(std::move(*opt_data));
				else
					{
					valid_args = false;
					auto_publish.clear();
					reporter->Error("failed auto-remote event '%s', disabled", Name());
					break;
					}
				}

			if ( valid_args )
				{
				for ( auto it = auto_publish.begin(); ; )
					{
					const auto& topic = *it;
					++it;

					if ( it != auto_publish.end() )
						broker_mgr->PublishEvent(topic, Name(), xs);
					else
						{
						broker_mgr->PublishEvent(topic, Name(), std::move(xs));
						break;
						}
					}
				}
			}
		}

	if ( local )
		// No try/catch here; we pass exceptions upstream.
		local->Call(vl);
	}

void EventHandler::NewEvent(const zeek::Args& vl)
	{
	if ( ! new_event )
		return;

	if ( this == new_event.Ptr() )
		// new_event() is the one event we don't want to report.
		return;

	RecordType* args = FType()->Args();
	auto vargs = make_intrusive<VectorVal>(zeek::vars::call_argument_vector);

	for ( int i = 0; i < args->NumFields(); i++ )
		{
		const char* fname = args->FieldName(i);
		const auto& ftype = args->GetFieldType(i);
		auto fdefault = args->FieldDefault(i);

		auto rec = make_intrusive<RecordVal>(zeek::vars::call_argument);
		rec->Assign(0, make_intrusive<StringVal>(fname));

		ODesc d;
		d.SetShort();
		ftype->Describe(&d);
		rec->Assign(1, make_intrusive<StringVal>(d.Description()));

		if ( fdefault )
			rec->Assign(2, std::move(fdefault));

		if ( i < static_cast<int>(vl.size()) && vl[i] )
			rec->Assign(3, vl[i]);

		vargs->Assign(i, std::move(rec));
		}

	Event* ev = new Event(new_event, {
		make_intrusive<StringVal>(name),
		std::move(vargs),
	});
	mgr.Dispatch(ev);
	}

