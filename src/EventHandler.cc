// $Id: EventHandler.cc 5911 2008-07-03 22:59:01Z vern $

#include "Event.h"
#include "EventHandler.h"
#include "Func.h"
#include "Scope.h"
#include "RemoteSerializer.h"

EventHandler::EventHandler(const char* arg_name)
	{
	name = copy_string(arg_name);
	used = false;
	local = 0;
	type = 0;
	group = 0;
	enabled = true;
	}

EventHandler::~EventHandler()
	{
	Unref(local);
	delete [] name;
	delete [] group;
	}

EventHandler::operator bool() const
	{
	return enabled && ((local && local->HasBodies()) || receivers.length());
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

	return type = id->Type()->AsFuncType();
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

	if ( ! no_remote )
		{
		loop_over_list(receivers, i)
			{
			SerialInfo info(remote_serializer);
			remote_serializer->SendCall(&info, receivers[i], name, vl);
			}
		}

	if ( local )
		{
		if ( FType() )
			{
			const type_list* arg_types = type->ArgTypes()->Types();
			loop_over_list(*vl, i)
				{
				Val* v = (*vl)[i];
				BroType* va_t = v->Type();
				BroType* ar_t = (*arg_types)[i];
				if ( va_t->Tag() == TYPE_RECORD && ar_t->Tag() == TYPE_RECORD )
					{
					if ( ! same_type(va_t, ar_t) )
						{
						Val* nv;
						nv = v->AsRecordVal()->CoerceTo(ar_t->AsRecordType());
						if ( nv )
							{
							vl->replace(i, nv);
							Unref(v);
							}
						}
					}
				}
			}
		Unref(local->Call(vl));
		}
	else
		{
		loop_over_list(*vl, i)
			Unref((*vl)[i]);
		}
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
		return false;

	EventHandler* h = event_registry->Lookup(name);
	if ( ! h )
		{
		h = new EventHandler(name);
		event_registry->Register(h);
		}

	return h;
	}
