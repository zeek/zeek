// See the file "COPYING" in the main distribution directory for copyright.
//
// Log writer for writing to an ElasticSearchRabbit database
//
// This is experimental code that is not yet ready for production usage.
//

#ifndef LOGGING_WRITER_ELASTICSEARCHRABBIT_H
#define LOGGING_WRITER_ELASTICSEARCHRABBIT_H

#include "threading/formatters/JSON.h"
#include "../WriterBackend.h"
#include <amqp.h>
#include <amqp_framing.h>

namespace logging { namespace writer {

class ElasticSearchRabbit : public WriterBackend {
public:
	ElasticSearchRabbit(WriterFrontend* frontend);
	~ElasticSearchRabbit();

	static WriterBackend* Instantiate(WriterFrontend* frontend)
		{ return new ElasticSearchRabbit(frontend); }
	static string LogExt();

protected:
	// Overidden from WriterBackend.

	virtual bool DoInit(const WriterInfo& info, int num_fields,
			    const threading::Field* const* fields);

	virtual bool DoWrite(int num_fields, const threading::Field* const* fields,
			     threading::Value** vals);
	virtual bool DoSetBuf(bool enabled);
	virtual bool DoRotate(const char* rotated_path, double open,
			      double close, bool terminating);
	virtual bool DoFlush(double network_time);
	virtual bool DoFinish(double network_time);
	virtual bool DoHeartbeat(double network_time, double current_time);

private:
	bool AddFieldToBuffer(ODesc *b, threading::Value* val, const threading::Field* field);
	bool AddValueToBuffer(ODesc *b, threading::Value* val);
	bool BatchIndex();
	bool UpdateIndex(double now, double rinterval, double rbase);
	bool RPCSuccess(::amqp_rpc_reply_t& reply);

	// Buffers, etc.
	ODesc buffer;
	uint64 counter;
	double last_send;
	string current_index;
	string prev_index;

	//amqp
	::amqp_connection_state_t connection;

	// From scripts
	char* server;
	int port;
	char* user;
	char* pass;
	char* exchange;
	char* key;


	string path;
	string index_prefix;
	long transfer_timeout;

	uint64 batch_size;

	threading::formatter::JSON* json;
};

}
}


#endif
