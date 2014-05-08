// See the file "COPYING" in the main distribution directory for copyright.
//

#include "config.h"

#ifdef USE_RABBIT

#include "util.h" // Needs to come first for stdint.h

#include <string>
#include <errno.h>

#include "BroString.h"
#include "NetVar.h"
#include "threading/SerialTypes.h"

#include "AMQP.h"

#include <amqp.h> //From librabbitmq
#include <amqp_tcp_socket.h>
#include <amqp_framing.h>

using namespace logging;
using namespace writer;
using threading::Value;
using threading::Field;

AMQP::AMQP(WriterFrontend* frontend) : WriterBackend(frontend)
	{

	int server_len = BifConst::LogAMQP::server_host->Len();
	server = new char[server_len + 1];
	memcpy(server, BifConst::LogAMQP::server_host->Bytes(), server_len);
	server[server_len] = 0;

    port = (int) BifConst::LogAMQP::server_port;

	int user_len = BifConst::LogAMQP::server_user->Len();
	user = new char[user_len + 1];
	memcpy(user, BifConst::LogAMQP::server_user->Bytes(), user_len);
	user[user_len] = 0;

	int pass_len = BifConst::LogAMQP::server_pass->Len();
	pass = new char[pass_len + 1];
	memcpy(pass, BifConst::LogAMQP::server_pass->Bytes(), pass_len);
	pass[pass_len] = 0;

	int exchange_len = BifConst::LogAMQP::queue_exchange->Len();
	exchange = new char[exchange_len + 1];
	memcpy(exchange, BifConst::LogAMQP::queue_exchange->Bytes(), exchange_len);
	exchange[exchange_len] = 0;

	int key_len = BifConst::LogAMQP::routing_key->Len();
	key = new char[key_len + 1];
	memcpy(key, BifConst::LogAMQP::routing_key->Bytes(), key_len);
	key[key_len] = 0;


	buffer.Clear();
	counter = 0;
	current_index = string();
	prev_index = string();
	last_send = current_time();

    json = new threading::formatter::JSON(this, threading::formatter::JSON::TS_MILLIS);

}

AMQP::~AMQP()
	{
	delete [] server;
    delete [] user;
    delete [] pass;
    delete [] exchange;
    delete [] key;
	delete json;
	}

bool AMQP::DoInit(const WriterInfo& info, int num_fields, const threading::Field* const* fields)
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
    if (!RPCSuccess(result)){
        return false;
    }
    
    ::amqp_channel_open(conn, 1);
    result = ::amqp_get_rpc_reply(conn);
    if (!RPCSuccess(result)){
        return false;
    }
    
    connection = conn;

	return true;
	}

bool AMQP::DoFlush(double network_time)
	{
    BatchIndex();
	return true;
	}

bool AMQP::DoFinish(double network_time)
	{
    BatchIndex();
    ::amqp_channel_close(connection, 1, AMQP_REPLY_SUCCESS);
    ::amqp_connection_close(connection, AMQP_REPLY_SUCCESS);
	return true;
	}

bool AMQP::BatchIndex()
	{
    //Push data to queue

    string topic_key = string(Fmt("%s.%s", key, Info().path));

    int status;
    status = ::amqp_basic_publish(connection, 1, ::amqp_cstring_bytes(exchange), 
                ::amqp_cstring_bytes(topic_key.c_str()), 0, 0, NULL, 
                ::amqp_cstring_bytes( (const char* ) (buffer.Bytes()) ));

	buffer.Clear();
	counter = 0;
	last_send = current_time();
    
    //For now just check status and return false on failure
    if (status != 0){
        return false;
    }

	return true;
	}

bool AMQP::DoWrite(int num_fields, const Field* const * fields,
			     Value** vals)
	{

    json->Describe(&buffer, num_fields, fields, vals);
	buffer.AddRaw("\n", 1);

	counter++;
	if ( counter >= BifConst::LogElasticSearchRabbit::max_batch_size ||
	     uint(buffer.Len()) >= BifConst::LogElasticSearchRabbit::max_byte_size )
		BatchIndex();

	return true;
	}

bool AMQP::DoRotate(const char* rotated_path, double open, double close, bool terminating)
	{
	return true;
	}

bool AMQP::DoSetBuf(bool enabled)
	{
	// Nothing to do.
	return true;
	}

bool AMQP::DoHeartbeat(double network_time, double current_time)
	{
	if ( last_send > 0 && buffer.Len() > 0 &&
	     current_time-last_send > BifConst::LogAMQP::max_batch_interval )
		{
		BatchIndex();
		}
	return true;
	}


bool AMQP::RPCSuccess(::amqp_rpc_reply_t& reply)
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
