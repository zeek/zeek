#include "zeek/EventHandler.h"

#include "zeek/Event.h"
#include "zeek/Desc.h"
#include "zeek/Func.h"
#include "zeek/Scope.h"
#include "zeek/NetVar.h"
#include "zeek/ID.h"
#include "zeek/Var.h"

#include "zeek/broker/Manager.h"
#include "zeek/broker/Data.h"

namespace zeek {

EventHandler::EventHandler(std::string arg_name)
	{
	name = std::move(arg_name);
	used = false;
	error_handler = false;
	enabled = true;
	generate_always = false;
	}

EventHandler::operator bool() const
	{
	return enabled && ((local && local->HasBodies())
			   || generate_always
			   || ! auto_publish.empty());
	}

const FuncTypePtr& EventHandler::GetType(bool check_export)
	{
	if ( type )
		return type;

	const auto& id = detail::lookup_ID(name.data(), detail::current_module.c_str(),
	                                   false, false, check_export);

	if ( ! id )
		return FuncType::nil;

	if ( id->GetType()->Tag() != TYPE_FUNC )
		return FuncType::nil;

	type = id->GetType<FuncType>();
	return type;
	}

void EventHandler::SetFunc(FuncPtr f)
	{ local = std::move(f); }

void EventHandler::Call(Args* vl, bool no_remote)
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
			xs.reserve(vl->size());
			bool valid_args = true;

			for ( auto i = 0u; i < vl->size(); ++i )
				{
				auto opt_data = Broker::detail::val_to_data((*vl)[i].get());

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
		local->Invoke(vl);
	}

void EventHandler::NewEvent(Args* vl)
	{
	if ( ! new_event )
		return;

	if ( this == new_event.Ptr() )
		// new_event() is the one event we don't want to report.
		return;

	auto vargs = MakeCallArgumentVector(*vl, GetType()->Params());

	auto ev = new Event(new_event, {
			make_intrusive<StringVal>(name),
			std::move(vargs),
			});
	event_mgr.Dispatch(ev);
	}

} // namespace zeek
