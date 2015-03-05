#include "Event.h"
#include "EventHandler.h"
#include "Func.h"
#include "Scope.h"
#include "RemoteSerializer.h"
#include "NetVar.h"

#ifdef ENABLE_BROKER
#include "broker/Manager.h"
#include "broker/Data.h"
#endif

EventHandler::EventHandler(const char* arg_name)
	{
	name = copy_string(arg_name);
	used = false;
	local = 0;
	type = 0;
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
			   || receivers.length()
			   || generate_always
#ifdef ENABLE_BROKER
			   || ! auto_remote_send.empty()
			   // TODO: and require a subscriber interested in a topic or unsolicited flags?
#endif
	                   );
	}

FuncType* EventHandler::FType()
	{
	if ( type )
		return type;

	ID* id = lookup_ID(name, current_module.c_str());

	if ( ! id )
		return 0;

	if ( id->Type()->Tag() != TYPE_FUNC )
		return 0;

	type = id->Type()->AsFuncType();
	Unref(id);

	return type;
	}

void EventHandler::SetLocalHandler(Func* f)
	{
	if ( local )
		Unref(local);

	Ref(f);
	local = f;
	}

void EventHandler::Call(val_list* vl, bool no_remote)
	{
#ifdef PROFILE_BRO_FUNCTIONS
	DEBUG_MSG("Event: %s\n", Name());
#endif

	if ( new_event )
		NewEvent(vl);

	if ( ! no_remote )
		{
		loop_over_list(receivers, i)
			{
			SerialInfo info(remote_serializer);
			remote_serializer->SendCall(&info, receivers[i], name, vl);
			}

#ifdef ENABLE_BROKER

		if ( ! auto_remote_send.empty() )
			{
			// TODO: also short-circuit based on interested subscribers/flags?
			broker::message msg;
			msg.reserve(vl->length() + 1);
			msg.emplace_back(Name());
			bool valid_args = true;

			for ( auto i = 0; i < vl->length(); ++i )
				{
				auto opt_data = bro_broker::val_to_data((*vl)[i]);

				if ( opt_data )
					msg.emplace_back(move(*opt_data));
				else
					{
					valid_args = false;
					auto_remote_send.clear();
					reporter->Error("failed auto-remote event '%s', disabled",
					                Name());
					break;
					}
				}

			if ( valid_args )
				{
				for ( auto it = auto_remote_send.begin();
				      it != auto_remote_send.end(); ++it )
					{
					if ( std::next(it) == auto_remote_send.end() )
						broker_mgr->Event(it->first, move(msg), it->second);
					else
						broker_mgr->Event(it->first, msg, it->second);
					}
				}
			}
#endif
		}

	if ( local )
		// No try/catch here; we pass exceptions upstream.
		Unref(local->Call(vl));
	else
		{
		loop_over_list(*vl, i)
			Unref((*vl)[i]);
		}
	}

void EventHandler::NewEvent(val_list* vl)
	{
	if ( ! new_event )
		return;

	if ( this == new_event.Ptr() )
		// new_event() is the one event we don't want to report.
		return;

	RecordType* args = FType()->Args();
	VectorVal* vargs = new VectorVal(call_argument_vector);

	for ( int i = 0; i < args->NumFields(); i++ )
		{
		const char* fname = args->FieldName(i);
		BroType* ftype = args->FieldType(i);
		Val* fdefault = args->FieldDefault(i);

		RecordVal* rec = new RecordVal(call_argument);
		rec->Assign(0, new StringVal(fname));

		ODesc d;
		d.SetShort();
		ftype->Describe(&d);
		rec->Assign(1, new StringVal(d.Description()));

		if ( fdefault )
			{
			Ref(fdefault);
			rec->Assign(2, fdefault);
			}

		if ( i < vl->length() && (*vl)[i] )
			{
			Val* val = (*vl)[i];
			Ref(val);
			rec->Assign(3, val);
			}

		vargs->Assign(i, rec);
		}

	val_list* mvl = new val_list(2);
	mvl->append(new StringVal(name));
	mvl->append(vargs);

	Event* ev = new Event(new_event, mvl);
	mgr.Dispatch(ev);
	}

void EventHandler::AddRemoteHandler(SourceID peer)
	{
	receivers.append(peer);
	}

void EventHandler::RemoveRemoteHandler(SourceID peer)
	{
	receivers.remove(peer);
	}

bool EventHandler::Serialize(SerialInfo* info) const
	{
	return SERIALIZE(name);
	}

EventHandler* EventHandler::Unserialize(UnserialInfo* info)
	{
	char* name;
	if ( ! UNSERIALIZE_STR(&name, 0) )
		return 0;

	EventHandler* h = event_registry->Lookup(name);
	if ( ! h )
		{
		h = new EventHandler(name);
		event_registry->Register(h);
		}

	return h;
	}
