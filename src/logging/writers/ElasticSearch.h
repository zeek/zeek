// See the file "COPYING" in the main distribution directory for copyright.
//
// Log writer for writing to an ElasticSearch database

#ifndef LOGGING_WRITER_ELASTICSEARCH_H
#define LOGGING_WRITER_ELASTICSEARCH_H

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

private:
	char* AddFieldToBuffer(threading::Value* val, const threading::Field* field);
	char* FormatField(const char* field_name, const char* field_value);
	bool BatchIndex();
	
	char* buffer;
	int current_offset;
	int counter;

	// From scripts
	char* cluster_name;
	int cluster_name_len;

	char* server_host;
	int server_host_len;

	uint64 server_port;

	char* index_name;
	int index_name_len;

	char* type_prefix;
	int type_prefix_len;
	
	uint64 batch_size;

};

}
}


#endif
