// See the file "COPYING" in the main distribution directory for copyright.
//
// This is experimental code that is not yet ready for production usage.
//


#include "config.h"

#ifdef USE_ELASTICSEARCH
#ifdef USE_RABBIT

#include "util.h" // Needs to come first for stdint.h

#include <string>
#include <errno.h>

#include "BroString.h"
#include "NetVar.h"
#include "threading/SerialTypes.h"

#include "ElasticSearchRabbit.h"

#include <amqp.h>
#include <amqp_tcp_socket.h>
#include <amqp_framing.h>

using namespace logging;
using namespace writer;
using threading::Value;
using threading::Field;

ElasticSearchRabbit::ElasticSearchRabbit(WriterFrontend* frontend) : WriterBackend(frontend)
	{

	int server_len = BifConst::LogElasticSearchRabbit::server_host->Len();
	server = new char[server_len + 1];
	memcpy(server, BifConst::LogElasticSearchRabbit::server_host->Bytes(), server_len);
	server[server_len] = 0;

    port = (int) BifConst::LogElasticSearchRabbit::server_port;

	int user_len = BifConst::LogElasticSearchRabbit::server_user->Len();
	user = new char[user_len + 1];
	memcpy(user, BifConst::LogElasticSearchRabbit::server_user->Bytes(), user_len);
	user[user_len] = 0;

	int pass_len = BifConst::LogElasticSearchRabbit::server_pass->Len();
	pass = new char[pass_len + 1];
	memcpy(pass, BifConst::LogElasticSearchRabbit::server_pass->Bytes(), pass_len);
	pass[pass_len] = 0;

	int exchange_len = BifConst::LogElasticSearchRabbit::queue_exchange->Len();
	exchange = new char[exchange_len + 1];
	memcpy(exchange, BifConst::LogElasticSearchRabbit::queue_exchange->Bytes(), exchange_len);
	exchange[exchange_len] = 0;

	int key_len = BifConst::LogElasticSearchRabbit::routing_key->Len();
	key = new char[key_len + 1];
	memcpy(key, BifConst::LogElasticSearchRabbit::routing_key->Bytes(), key_len);
	key[key_len] = 0;


	index_prefix = string((const char*) BifConst::LogElasticSearchRabbit::index_prefix->Bytes(), BifConst::LogElasticSearchRabbit::index_prefix->Len());

	buffer.Clear();
	counter = 0;
	current_index = string();
	prev_index = string();
	last_send = current_time();

	json = new threading::formatter::JSON(this, threading::formatter::JSON::TS_MILLIS);
}

ElasticSearchRabbit::~ElasticSearchRabbit()
	{
	delete [] server;
    delete [] user;
    delete [] pass;
    delete [] exchange;
    delete [] key;
    delete json;
	}

bool ElasticSearchRabbit::DoInit(const WriterInfo& info, int num_fields, const threading::Field* const* fields)
	{
    ::amqp_socket_t *socket = NULL;
    int status;
    ::amqp_rpc_reply_t result;

    ::amqp_connection_state_t conn = ::amqp_new_connection();

    socket = ::amqp_tcp_socket_new();
    if(!socket){
        return false;
    }

    status = ::amqp_socket_open(socket, server, port);
    if(status){
        return false;
    }

    ::amqp_set_socket(conn, socket);

    result = ::amqp_login(conn, "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, user, pass);
    if(!RPCSuccess(result)){
        return false;
    } 
    
    ::amqp_channel_open(conn, 1);
    result = ::amqp_get_rpc_reply(conn);
    if(!RPCSuccess(result)){
        return false;
    } 
    
    connection = conn;
    
	return true;
	}

bool ElasticSearchRabbit::DoFlush(double network_time)
	{
	BatchIndex();
	return true;
	}

bool ElasticSearchRabbit::DoFinish(double network_time)
	{
	BatchIndex();

    ::amqp_channel_close(connection, 1, AMQP_REPLY_SUCCESS);
    ::amqp_connection_close(connection, AMQP_REPLY_SUCCESS);
	return true;
	}

bool ElasticSearchRabbit::BatchIndex()
	{
    //Push data to queue

    int status;

    status = ::amqp_basic_publish(connection, 1, ::amqp_cstring_bytes(exchange), ::amqp_cstring_bytes(key), 
                                0, 0, NULL, ::amqp_cstring_bytes( (const char* ) (buffer.Bytes()) ));

	buffer.Clear();
	counter = 0;
	last_send = current_time();

	return true;
	}

bool ElasticSearchRabbit::DoWrite(int num_fields, const Field* const * fields,
			     Value** vals)
	{
	if ( current_index.empty() )
		UpdateIndex(network_time, Info().rotation_interval, Info().rotation_base);

	// Our action line looks like:
	buffer.AddRaw("{\"index\":{\"_index\":\"", 20);
	buffer.Add(current_index);
	buffer.AddRaw("\",\"_type\":\"", 11);
	buffer.Add(Info().path);
	buffer.AddRaw("\"}}\n", 4);

    json->Describe(&buffer, num_fields, fields, vals);
	buffer.AddRaw("\n", 1);

	counter++;
	if ( counter >= BifConst::LogElasticSearchRabbit::max_batch_size ||
	     uint(buffer.Len()) >= BifConst::LogElasticSearchRabbit::max_byte_size )
		BatchIndex();

	return true;
	}

bool ElasticSearchRabbit::UpdateIndex(double now, double rinterval, double rbase)
	{
	if ( rinterval == 0 )
		{
		// if logs aren't being rotated, don't use a rotation oriented index name.
		current_index = index_prefix;
		}
	else
		{
		double nr = calc_next_rotate(now, rinterval, rbase);
		double interval_beginning = now - (rinterval - nr);

		struct tm tm;
		char buf[128];
		time_t teatime = (time_t)interval_beginning;
		localtime_r(&teatime, &tm);
		strftime(buf, sizeof(buf), "%Y%m%d%H%M", &tm);

		prev_index = current_index;
		current_index = index_prefix + "-" + buf;

		// Send some metadata about this index.
		buffer.AddRaw("{\"index\":{\"_index\":\"@", 21);
		buffer.Add(index_prefix);
		buffer.AddRaw("-meta\",\"_type\":\"index\",\"_id\":\"", 30);
		buffer.Add(current_index);
		buffer.AddRaw("-", 1);
		buffer.Add(Info().rotation_base);
		buffer.AddRaw("-", 1);
		buffer.Add(Info().rotation_interval);
		buffer.AddRaw("\"}}\n{\"name\":\"", 13);
		buffer.Add(current_index);
		buffer.AddRaw("\",\"start\":", 10);
		buffer.Add(interval_beginning);
		buffer.AddRaw(",\"end\":", 7);
		buffer.Add(interval_beginning+rinterval);
		buffer.AddRaw("}\n", 2);
		}

	return true;
	}


bool ElasticSearchRabbit::DoRotate(const char* rotated_path, double open, double close, bool terminating)
	{
	// Update the currently used index to the new rotation interval.
	UpdateIndex(close, Info().rotation_interval, Info().rotation_base);

	if ( ! FinishedRotation(current_index.c_str(), prev_index.c_str(), open, close, terminating) )
		Error(Fmt("error rotating %s to %s", prev_index.c_str(), current_index.c_str()));

	return true;
	}

bool ElasticSearchRabbit::DoSetBuf(bool enabled)
	{
	// Nothing to do.
	return true;
	}

bool ElasticSearchRabbit::DoHeartbeat(double network_time, double current_time)
	{
	if ( last_send > 0 && buffer.Len() > 0 &&
	     current_time-last_send > BifConst::LogElasticSearchRabbit::max_batch_interval )
		{
		BatchIndex();
		}

	return true;
	}

bool ElasticSearchRabbit::RPCSuccess(::amqp_rpc_reply_t& reply)
{
  switch (reply.reply_type) {
    case AMQP_RESPONSE_NORMAL:
      return true;

    case AMQP_RESPONSE_NONE:
      break;
    case AMQP_RESPONSE_LIBRARY_EXCEPTION:
      break;
    case AMQP_RESPONSE_SERVER_EXCEPTION:
      switch (reply.reply.id) {
        case AMQP_CONNECTION_CLOSE_METHOD: 
        {
         ::amqp_connection_close_t *m = (amqp_connection_close_t *) reply.reply.decoded;
         break;
        }
        case AMQP_CHANNEL_CLOSE_METHOD: 
        {
          ::amqp_channel_close_t *m = (amqp_channel_close_t *) reply.reply.decoded;
          break;
        }
        default:
            break;
      }
      break;
  }

    return false;
}

#endif
#endif
