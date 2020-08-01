#include "EventHandler.h"
#include "Event.h"
#include "Desc.h"
#include "Func.h"
#include "Scope.h"
#include "NetVar.h"
#include "ID.h"
#include "Var.h"

#include "broker/Manager.h"
#include "broker/Data.h"

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

const zeek::FuncTypePtr& EventHandler::GetType(bool check_export)
	{
	if ( type )
		return type;

	const auto& id = zeek::detail::lookup_ID(name.data(), zeek::detail::current_module.c_str(),
	                                         false, false, check_export);

	if ( ! id )
		return zeek::FuncType::nil;

	if ( id->GetType()->Tag() != zeek::TYPE_FUNC )
		return zeek::FuncType::nil;

	type = id->GetType<zeek::FuncType>();
	return type;
	}

void EventHandler::SetFunc(zeek::FuncPtr f)
	{ local = std::move(f); }

void EventHandler::SetLocalHandler(zeek::Func* f)
	{ SetFunc({zeek::NewRef{}, f}); }

void EventHandler::Call(zeek::Args* vl, bool no_remote)
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
				auto opt_data = zeek::Broker::detail::val_to_data((*vl)[i].get());

				if ( opt_data )
					xs.emplace_back(std::move(*opt_data));
				else
					{
					valid_args = false;
					auto_publish.clear();
					zeek::reporter->Error("failed auto-remote event '%s', disabled", Name());
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

void EventHandler::NewEvent(zeek::Args* vl)
	{
	if ( ! new_event )
		return;

	if ( this == new_event.Ptr() )
		// new_event() is the one event we don't want to report.
		return;

	auto vargs = zeek::MakeCallArgumentVector(*vl, GetType()->Params());

	auto ev = new zeek::Event(new_event, {
			zeek::make_intrusive<zeek::StringVal>(name),
			std::move(vargs),
			});
	zeek::event_mgr.Dispatch(ev);
	}

} // namespace zeek
