#include "Manager.h"
#include "Data.h"
#include "Store.h"
#include <broker/broker.hh>
#include <cstdio>
#include <unistd.h>
#include "util.h"
#include "Var.h"
#include "Reporter.h"
#include "broker/comm.bif.h"
#include "broker/data.bif.h"
#include "broker/messaging.bif.h"
#include "broker/store.bif.h"
#include "logging/Manager.h"
#include "DebugLogger.h"
#include "iosource/Manager.h"

using namespace std;

namespace bro_broker {

VectorType* Manager::vector_of_data_type;
EnumType* Manager::log_id_type;

Manager::Manager()
	: next_timestamp(-1)
	{
	SetIdle(true);
	}

Manager::~Manager()
	{
	vector<string> stores_to_close;

	for ( auto& x : data_stores )
		stores_to_close.push_back(x.first);

	for ( auto& x: stores_to_close )
		// This doesn't loop directly over data_stores, because CloseStore
		// modifies the map and invalidates iterators.
		CloseStore(x);
	}

static int require_field(RecordType* rt, const char* name)
	{
	auto rval = rt->FieldOffset(name);

	if ( rval < 0 )
		reporter->InternalError("no field named '%s' in record type '%s'", name,
		                        rt->GetName().data());

	return rval;
	}

bool Manager::Enable(std::string endpoint_name, bool routable)
	{
	if ( Enabled() )
		return true;

	log_id_type = internal_type("Log::ID")->AsEnumType();

	opaque_of_data_type = new OpaqueType("Broker::Data");
	opaque_of_set_iterator = new OpaqueType("Broker::SetIterator");
	opaque_of_table_iterator = new OpaqueType("Broker::TableIterator");
	opaque_of_vector_iterator = new OpaqueType("Broker::VectorIterator");
	opaque_of_record_iterator = new OpaqueType("Broker::RecordIterator");
	opaque_of_store_handle = new OpaqueType("Broker::Handle");
	vector_of_data_type = new VectorType(internal_type("Broker::Data")->Ref());

  name = std::move(endpoint_name);
  // TODO: process routable flag
	endpoint = context.spawn<broker::blocking>();

	iosource_mgr->Register(this, true);

	return true;
	}

uint16_t Manager::Listen(const string& addr, uint16_t port)
	{
	if ( ! Enabled() )
		return false;

	auto bound_port = endpoint.listen(addr, port);

	if ( bound_port == 0 )
		reporter->Error("Failed to listen on %s:%" PRIu16,
		                addr.empty() ? "INADDR_ANY" : addr.c_str(), port);

	return bound_port;
	}

void Manager::Peer(const string& addr, uint16_t port)
	{
	if ( Enabled() )
    endpoint.peer(addr, port);
	}

void Manager::Unpeer(const string& addr, uint16_t port)
	{
	if ( Enabled() )
    endpoint.unpeer(addr, port);
	}

bool Manager::Publish(broker::message msg)
	{
	if ( ! Enabled() )
		return false;

	endpoint.publish(std::move(msg));
	return true;
	}

bool Manager::Publish(string topic, broker::data x)
	{
	if ( ! Enabled() )
		return false;

	endpoint.publish(move(topic), move(x));
	return true;
	}

bool Manager::Publish(EnumVal* stream, RecordVal* columns,
                              RecordType* info)
	{
	if ( ! Enabled() )
		return false;

	auto stream_name = stream->Type()->AsEnumType()->Lookup(stream->AsEnum());

	if ( ! stream_name )
		{
		reporter->Error("Failed to remotely log: stream %d doesn't have name",
		                stream->AsEnum());
		return false;
		}

	broker::vector xs;
	xs.reserve(info->NumFields() + 1);
	xs.emplace_back(broker::enum_value{stream_name});

	for ( auto i = 0u; i < static_cast<size_t>(info->NumFields()); ++i )
		{
		if ( ! info->FieldDecl(i)->FindAttr(ATTR_LOG) )
			continue;

		auto field_val = columns->LookupWithDefault(i);

		if ( ! field_val )
			{
			xs.emplace_back(broker::nil);
			continue;
			}

		auto field_data = val_to_data(field_val);
		Unref(field_val);

		if ( ! field_data )
			{
			reporter->Error("Failed to remotely log stream %s: "
			                "unsupported type '%s'",
			                stream_name,
			                type_name(info->FieldDecl(i)->type->Tag()));
			return false;
			}

		xs.push_back(move(*field_data));
		}

	auto stream_enum = broker::enum_value{stream_name};
	auto topic = "bro/log"_t / stream_name;
	endpoint.publish(move(topic), broker::vector{stream_enum, move(xs)});
	return true;
	}

bool Manager::Publish(string topic, RecordVal* args)
	{
	if ( ! Enabled() )
		return false;

	if ( ! args->Lookup(0) )
		return false;

	auto event_name = args->Lookup(0)->AsString()->CheckString();
	auto vv = args->Lookup(1)->AsVectorVal();
	broker::vector xs;
	xs.reserve(vv->Size() + 1);
	xs.emplace_back(event_name);

	for ( auto i = 0u; i < vv->Size(); ++i )
		{
		auto val = vv->Lookup(i)->AsRecordVal()->Lookup(0);
		auto data_val = static_cast<DataVal*>(val);
		xs.emplace_back(data_val->data);
		}

	endpoint.publish(move(topic), move(xs));
	return true;
	}

bool Manager::AutoPublish(string topic, Val* event)
	{
	if ( ! Enabled() )
		return false;

	if ( event->Type()->Tag() != TYPE_FUNC )
		{
		reporter->Error("Broker::auto_event must operate on an event");
		return false;
		}

	auto event_val = event->AsFunc();

	if ( event_val->Flavor() != FUNC_FLAVOR_EVENT )
		{
		reporter->Error("Broker::auto_event must operate on an event");
		return false;
		}

	auto handler = event_registry->Lookup(event_val->Name());

	if ( ! handler )
		{
		reporter->Error("Broker::auto_event failed to lookup event '%s'",
		                event_val->Name());
		return false;
		}

	handler->AutoRemote(move(topic));
	return true;
	}

bool Manager::AutoUnpublish(const string& topic, Val* event)
	{
	if ( ! Enabled() )
		return false;

	if ( event->Type()->Tag() != TYPE_FUNC )
		{
		reporter->Error("Broker::auto_event_stop must operate on an event");
		return false;
		}

	auto event_val = event->AsFunc();

	if ( event_val->Flavor() != FUNC_FLAVOR_EVENT )
		{
		reporter->Error("Broker::auto_event_stop must operate on an event");
		return false;
		}

	auto handler = event_registry->Lookup(event_val->Name());

	if ( ! handler )
		{
		reporter->Error("Broker::auto_event_stop failed to lookup event '%s'",
		                event_val->Name());
		return false;
		}


	handler->AutoRemoteStop(topic);
	return true;
	}

RecordVal* Manager::MakeEvent(val_list* args)
	{
	if ( ! Enabled() )
		return nullptr;

	auto rval = new RecordVal(BifType::Record::Broker::Event);
	auto arg_vec = new VectorVal(vector_of_data_type);
	rval->Assign(1, arg_vec);
	Func* func = 0;

	for ( auto i = 0; i < args->length(); ++i )
		{
		auto arg_val = (*args)[i];

		if ( i == 0 )
			{
			// Event val must come first.

			if ( arg_val->Type()->Tag() != TYPE_FUNC )
				{
				reporter->Error("1st param of Broker::event_args must be event");
				return rval;
				}

			func = arg_val->AsFunc();

			if ( func->Flavor() != FUNC_FLAVOR_EVENT )
				{
				reporter->Error("1st param of Broker::event_args must be event");
				return rval;
				}

			auto num_args = func->FType()->Args()->NumFields();

			if ( num_args != args->length() - 1 )
				{
				reporter->Error("bad # of Broker::event_args: got %d, expect %d",
				                args->length(), num_args + 1);
				return rval;
				}

			rval->Assign(0, new StringVal(func->Name()));
			continue;
			}

		auto expected_type = (*func->FType()->ArgTypes()->Types())[i - 1];

		if ( ! same_type((*args)[i]->Type(), expected_type) )
			{
			rval->Assign(0, 0);
			reporter->Error("Broker::event_args param %d type mismatch", i);
			return rval;
			}

		auto data_val = make_data_val((*args)[i]);

		if ( ! data_val->Lookup(0) )
			{
			Unref(data_val);
			rval->Assign(0, 0);
			reporter->Error("Broker::event_args unsupported event/params");
			return rval;
			}

		arg_vec->Assign(i - 1, data_val);
		}

	return rval;
	}

bool Manager::Subscribe(const string& topic_prefix)
	{
	if ( ! Enabled() )
		return false;

  endpoint.subscribe(topic_prefix);
	return true;
	}

bool Manager::Unsubscribe(const string& topic_prefix)
	{
	if ( ! Enabled() )
		return false;

  endpoint.unsubscribe(topic_prefix);
	return true;
	}

void Manager::GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
                           iosource::FD_Set* except)
	{
	read->Insert(endpoint.mailbox().descriptor());

	for ( auto& x : data_stores )
	  read->Insert(x.second->proxy.mailbox().descriptor());
	}

double Manager::NextTimestamp(double* local_network_time)
	{
	if ( next_timestamp < 0 )
		next_timestamp = timer_mgr->Time();

	return next_timestamp;
	}

void Manager::Process()
	{
	assert(endpoint);

  while ( ! endpoint.mailbox().empty() )
    {
    auto elem = endpoint.receive();

    if ( auto msg = broker::get_if<broker::message>(elem) )
      {
      // All valid messages have non-empty vector data.
      auto xs = broker::get_if<broker::vector>(msg->data());
      if ( ! xs )
        {
        reporter->Warning("ignoring message with non-vector data");
        continue;
        }

      if ( xs->empty() )
        {
        reporter->Warning("ignoring message with empty vector data");
        continue;
        }

      if ( msg->topic() == "bro/log" )
        {
        // Process log messages.
        if ( xs->size() != 2 )
          {
          reporter->Warning("got bad remote log size: %zd (expected 2)",
                            xs->size());
          continue;
          }

        if ( ! broker::get_if<broker::enum_value>(xs->front()) )
          {
          reporter->Warning("got remote log w/o stream id");
          continue;
          }

        if ( ! broker::get_if<broker::vector>(xs->back()) )
          {
          reporter->Warning("got remote log w/o columns");
          continue;
          }

        auto stream_id = data_to_val(move(xs->front()), log_id_type);

        if ( ! stream_id )
          {
          reporter->Warning("failed to unpack remote log stream id");
          continue;
          }

        auto columns_type = log_mgr->StreamColumns(stream_id->AsEnumVal());
        if ( ! columns_type )
          {
          reporter->Warning("got remote log for unknown stream: %s",
                            stream_id->Type()->AsEnumType()->Lookup(
                                stream_id->AsEnum()));
          Unref(stream_id);
          continue;
          }

        auto columns = data_to_val(move(xs->back()), columns_type, true);
        if ( ! columns )
          {
          reporter->Warning("failed to unpack remote log stream columns"
                            " for stream: %s",
                            stream_id->Type()->AsEnumType()->Lookup(
                                stream_id->AsEnum()));
          Unref(stream_id);
          continue;
          }

        log_mgr->Write(stream_id->AsEnumVal(), columns->AsRecordVal());
        Unref(stream_id);
        Unref(columns);
        }
      else
        {
        // All other messages are event subscriptions.
        auto event_name = broker::get_if<string>((*xs)[0]);
        if ( ! event_name )
          {
          reporter->Warning("ignoring message without event name");
          continue;
          }

        auto handler = event_registry->Lookup(event_name->c_str());
        if ( ! handler )
          continue;

        auto arg_types = handler->FType()->ArgTypes()->Types();
        if ( static_cast<size_t>(arg_types->length()) != xs->size() - 1 )
          {
          reporter->Warning("got event message with invalid # of args,"
                            " got %zd, expected %d", xs->size() - 1,
                            arg_types->length());
          continue;
          }

        auto vl = new val_list;

        for ( auto i = 1u; i < xs->size(); ++i )
          {
          auto val = data_to_val(move((*xs)[i]), (*arg_types)[i - 1]);

          if ( val )
            vl->append(val);
          else
            {
            reporter->Warning("failed to convert remote event arg # %d", i - 1);
            break;
            }
          }

        if ( static_cast<size_t>(vl->length()) == xs->size() - 1 )
          mgr.QueueEvent(handler, vl);
        else
          delete_vals(vl);
        }
      }
    if ( auto stat = broker::get_if<broker::status>(elem) )
      {
        // TODO: handle status message properly.
      }
    else
      {
      // Not a data message, dispatch status accordingly.
      reporter->Warning("got status message: %s",
                        to_string(broker::get<broker::error>(elem)).c_str());
      }
    }

	for ( auto& s : data_stores )
		{
		while ( ! s.second->proxy.mailbox().empty() )
      {
      auto response = s.second->proxy.receive();

      auto request = pending_queries.find(response.id);
      if ( request == pending_queries.end() )
				{
				reporter->Warning("unmatched response to query %llu on store %s",
				                  response.id, s.second->store.name().c_str());
				continue;
				}

      if ( request->second->Disabled() )
        {
        // Trigger timer must have timed the query out already.
        delete request->second;
        pending_queries.erase(request);
        continue;
        }

      if ( response.answer )
        request->second->Result(query_result(make_data_val(*response.answer)));
      else if ( response.answer.error() == broker::ec::request_timeout )
				; // Fine, trigger's timeout takes care of things.
      else if ( response.answer.error() == broker::ec::no_such_key )
				request->second->Result(query_result());
      else
				reporter->InternalWarning("unknown store response status: %s",
                                  to_string(response.answer.error()).c_str());

      delete request->second;
			pending_queries.erase(request);
			}
		}

	next_timestamp = -1;
	}

StoreHandleVal* Manager::MakeMaster(const string& name, broker::backend type,
                                    broker::backend_options opts)
	{
	if ( ! Enabled() )
		return nullptr;

	if ( LookupStore(name) )
		return nullptr;

  auto result = endpoint.attach<broker::master>(name, type, move(opts));
  if ( ! result )
    {
		reporter->Error("Failed to attach master store %s:",
		                to_string(result.error()).c_str());
		return nullptr;
    }

  auto handle = new StoreHandleVal{*result};
	Ref(handle);

  data_stores.emplace(name, handle);

	return handle;
	}

StoreHandleVal* Manager::MakeClone(const string& name)
	{
	if ( ! Enabled() )
		return nullptr;

	if ( LookupStore(name) )
		return nullptr;

  auto result = endpoint.attach<broker::clone>(name);
  if ( ! result )
    {
		reporter->Error("Failed to attach clone store %s:",
		                to_string(result.error()).c_str());
		return nullptr;
    }

  auto handle = new StoreHandleVal{*result};
	Ref(handle);

  data_stores.emplace(name, handle);

	return handle;
	}

StoreHandleVal* Manager::LookupStore(const string& name)
	{
	if ( ! Enabled() )
		return nullptr;

	auto i = data_stores.find(name);
	return i == data_stores.end() ? nullptr : i->second;
	}

bool Manager::CloseStore(const string& name)
	{
	if ( ! Enabled() )
		return false;

	auto s = data_stores.find(name);
	if ( s == data_stores.end() )
		return false;

	for ( auto i = pending_queries.begin(); i != pending_queries.end(); )
		if ( i->second->Store().name() == name )
			{
			i->second->Abort();
			delete i->second;
			i = pending_queries.erase(i);
			}
		else
      {
			++i;
      }

	Unref(s->second);
	data_stores.erase(s);
	return true;
	}

bool Manager::TrackStoreQuery(broker::request_id id, StoreQueryCallback* cb)
	{
	assert(Enabled());
	return pending_queries.emplace(id, cb).second;
	}

Stats Manager::ConsumeStatistics()
	{
	return {}; // TODO
	}

} // namespace bro_broker
