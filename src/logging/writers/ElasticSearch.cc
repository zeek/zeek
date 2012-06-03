// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#ifdef USE_ELASTICSEARCH

#include <string>
#include <errno.h>

#include "util.h"

#include "NetVar.h"
#include "threading/SerialTypes.h"

#include "ElasticSearch.h"

using namespace logging;
using namespace writer;
using threading::Value;
using threading::Field;

#define MAX_EVENT_SIZE 1024

ElasticSearch::ElasticSearch(WriterFrontend* frontend) : WriterBackend(frontend)
	{
	cluster_name_len = BifConst::LogElasticSearch::cluster_name->Len();
	cluster_name = new char[cluster_name_len];
	memcpy(cluster_name, BifConst::LogElasticSearch::cluster_name->Bytes(), cluster_name_len);

	server_host_len = BifConst::LogElasticSearch::server_host->Len();
	server_host = new char[server_host_len];
	memcpy(server_host, BifConst::LogElasticSearch::server_host->Bytes(), server_host_len);

	index_name_len = BifConst::LogElasticSearch::index_name->Len();
	index_name = new char[index_name_len];
	memcpy(index_name, BifConst::LogElasticSearch::index_name->Bytes(), index_name_len);

	type_prefix_len = BifConst::LogElasticSearch::type_prefix->Len();
	type_prefix = new char[type_prefix_len];
	memcpy(type_prefix, BifConst::LogElasticSearch::type_prefix->Bytes(), type_prefix_len);

	server_port = BifConst::LogElasticSearch::server_port;
	batch_size = BifConst::LogElasticSearch::batch_size;

	buffer = safe_malloc(MAX_EVENT_SIZE * batch_size);
	current_offset = 0;
	buffer[current_offset] = "\0";
	counter = 0;
	}

ElasticSearch::~ElasticSearch()
	{
	delete [] cluster_name;
	delete [] server_host;
	delete [] index_name;
	delete [] type_prefix;
	delete [] buffer;
	}

bool ElasticSearch::DoInit(string path, int num_fields, const Field* const * fields)
	{
	  //TODO: Determine what, if anything, needs to be done here.
	return true;
	}

bool ElasticSearch::DoFlush()
	{
	  //TODO: Send flush command to ElasticSearch
	return true;
	}

bool ElasticSearch::DoFinish()
	{
	return WriterBackend::DoFinish();
	}

char* ElasticSearch::FormatField(const char* field_name, const char* field_value)
{
  char* result = new char[MAX_EVENT_SIZE];
  strcpy(result, "\"");
  strcpy(result, field_name);
  strcpy(result, "\":\"");
  strcpy(result, field_value);
  strcpy(result, "\"");
  return result;
  
}

bool ElasticSearch::BatchIndex()
{
  file = fopen("/tmp/batch.test", 'w');
  fwrite(buffer, current_offset, 1, file);
  fclose(file);
  file = 0;
}

char* ElasticSearch::AddFieldToBuffer(Value* val, const Field* field)
	{
    	if ( ! val->present )
		{
		  return "";
		}

	switch ( val->type ) {

	case TYPE_BOOL:
		return FormatField(field->name, val->val.int_val ? "T" : "F");

	case TYPE_INT:
		return FormatField(field->name, val->val.int_val);

	case TYPE_COUNT:
	case TYPE_COUNTER:
		return FormatField(field->name, val->val.uint_val);

	case TYPE_PORT:
		return FormatField(field->name, val->val.port_val.port);

	case TYPE_SUBNET:
	        return FormatField(field->name, Render(val->val.subnet_val));

	case TYPE_ADDR:
	        return FormatField(field->name, Render(val->val.addr_val));

	case TYPE_INTERVAL:
	case TYPE_TIME:	
	case TYPE_DOUBLE:
		return FormatField(field->name, val->val.double_val);

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		{
		int size = val->val.string_val->size();
		const char* data = val->val.string_val->data();

		if ( ! size )
			  return "";
		return FormatField(field->name, val->val.string_val->data());
		}

	case TYPE_TABLE:
		{
		if ( ! val->val.set_val.size )
		  return "";
		
		char* tmp = new char[MAX_EVENT_SIZE];
		strcpy(tmp, "{");
		for ( int j = 0; j < val->val.set_val.size; j++ )
			{
			  char* result = AddFieldToBuffer(val->val.set_val.vals[j], field);
			  bool resultSeen = false;
			  if ( result ){
			    if ( resultSeen )
			      strcpy(tmp, ",");
			    strcpy(tmp, result);
			  }
			}
		return FormatField(field->name, tmp);
		}

	case TYPE_VECTOR:
		{
		if ( ! val->val.vector_val.size )
		  return "";
		
		char* tmp = new char[MAX_EVENT_SIZE];
		strcpy(tmp, "{");
		for ( int j = 0; j < val->val.vector_val.size; j++ )
			{
			  char* result = AddFieldToBuffer(val->val.vector_val.vals[j], field);
			  bool resultSeen = false;
			  if ( result ){
			    if ( resultSeen )
			      strcpy(tmp, ",");
			    strcpy(tmp, result);
			  }
			}
		return FormatField(field->name, tmp);
		}

	default:
	  return "";
	}

	}

bool ElasticSearch::DoWrite(int num_fields, const Field* const * fields,
			     Value** vals)
	{
	  // Our action line looks like:
	  //   {"index":"$index_name","type":"$type_prefix$path"}\n{
	  
	  bool resultSeen = false;

	  for ( int i = 0; i < num_fields; i++ )
		{
		char* result = DoWriteOne(vals[i], fields[i]);
		if ( result ) {
		  if ( ! resultSeen ) {
		    strcpy(buffer[current_offset], "{\"index\":\"");
		    strcat(buffer[current_offset], index_name);
		    strcat(buffer[current_offset], "\",\"type\":\"");
		    strcat(buffer[current_offset], type_prefix);
		    strcat(buffer[current_offset], Path());
		    strcat(buffer[current_offset], "\"}\n{");
		    current_offset = strlen(buffer);
		    resultSeen = true;
		  }
		  else {
		    strcat(buffer[current_offset], ",");
		    current_offset += 1;
		  }
		  strcat(buffer[current_offset], result);
		  current_offset += strlen(result);
		}
	      }

	  if ( resultSeen ) {
	    strcat(buffer[current_offset], "}\n");
	    current_offset += 2;
	    counter += 1;
	    if ( counter >= batch_size )
	      BatchIndex();
	  }
	return true;
	}

bool ElasticSearch::DoRotate(string rotated_path, double open, double close, bool terminating)
	{
	  //TODO: Determine what, if anything, needs to be done here.
	return true;
	}

bool ElasticSearch::DoSetBuf(bool enabled)
	{
	// Nothing to do.
	return true;
	}

#endif
