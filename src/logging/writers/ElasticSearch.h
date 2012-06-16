// See the file "COPYING" in the main distribution directory for copyright.
//
// Log writer for writing to an ElasticSearch database

#ifndef LOGGING_WRITER_ELASTICSEARCH_H
#define LOGGING_WRITER_ELASTICSEARCH_H

#include <curl/curl.h>
#include "../WriterBackend.h"

namespace logging { namespace writer {

class ElasticSearch : public WriterBackend {
public:
	ElasticSearch(WriterFrontend* frontend);
	~ElasticSearch();

	static WriterBackend* Instantiate(WriterFrontend* frontend)
		{ return new ElasticSearch(frontend); }
	static string LogExt();

protected:
	// Overidden from WriterBackend.

	virtual bool DoInit(string path, int num_fields,
			    const threading::Field* const * fields);

	virtual bool DoWrite(int num_fields, const threading::Field* const* fields,
			     threading::Value** vals);
	virtual bool DoSetBuf(bool enabled);
	virtual bool DoRotate(string rotated_path, double open,
			      double close, bool terminating);
	virtual bool DoFlush();
	virtual bool DoFinish();
	virtual bool DoHeartbeat(double network_time, double current_time);

private:
	bool AddFieldToBuffer(threading::Value* val, const threading::Field* field);
	bool AddFieldValueToBuffer(threading::Value* val, const threading::Field* field);
	bool BatchIndex();
	
	CURL* HTTPSetup();
	bool HTTPReceive(void* ptr, int size, int nmemb, void* userdata);
	bool HTTPSend();
	
	// Buffers, etc.
	ODesc buffer;
	uint64 counter;
	double last_send;
	
	CURL* curl_handle;
	char* curl_result;
	
	// From scripts
	char* cluster_name;
	int cluster_name_len;
	
	uint64 batch_size;
};

}
}


#endif
