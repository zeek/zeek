// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#ifdef INSTALL_ELASTICSEARCH

#include <string>
#include <errno.h>

#include "util.h"

#include "NetVar.h"
#include "threading/SerialTypes.h"

#include <curl/curl.h>
#include <curl/easy.h>

#include "ElasticSearch.h"

using namespace logging;
using namespace writer;
using threading::Value;
using threading::Field;

#define MAX_EVENT_SIZE 1024

ElasticSearch::ElasticSearch(WriterFrontend* frontend) : WriterBackend(frontend)
	{
	cluster_name_len = BifConst::LogElasticSearch::cluster_name->Len();
	cluster_name = new char[cluster_name_len + 1];
	memcpy(cluster_name, BifConst::LogElasticSearch::cluster_name->Bytes(), cluster_name_len);
	cluster_name[cluster_name_len] = 0;

	server_host_len = BifConst::LogElasticSearch::server_host->Len();
	server_host = new char[server_host_len + 1];
	memcpy(server_host, BifConst::LogElasticSearch::server_host->Bytes(), server_host_len);
	server_host[server_host_len] = 0;

	index_name_len = BifConst::LogElasticSearch::index_name->Len();
	index_name = new char[index_name_len + 1];
	memcpy(index_name, BifConst::LogElasticSearch::index_name->Bytes(), index_name_len);
	index_name[index_name_len] = 0;

	type_prefix_len = BifConst::LogElasticSearch::type_prefix->Len();
	type_prefix = new char[type_prefix_len + 1];
	memcpy(type_prefix, BifConst::LogElasticSearch::type_prefix->Bytes(), type_prefix_len);
	type_prefix[type_prefix_len] = 0;

	server_port = BifConst::LogElasticSearch::server_port;
	batch_size = BifConst::LogElasticSearch::batch_size;

	buffer = (char *)safe_malloc(MAX_EVENT_SIZE * batch_size);
	current_offset = 0;
	buffer[current_offset] = 0;
	counter = 0;

	curl_handle = HTTPSetup();
	curl_result = new char[1024];
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

bool ElasticSearch::BatchIndex()
{
  return HTTPSend();
}

char* ElasticSearch::FieldToString(Value* val, const Field* field)
{
  char* result = new char[MAX_EVENT_SIZE];

  switch ( val->type ) {

    // ElasticSearch defines bools as: 0 == false, everything else == true. So we treat it as an int.
  case TYPE_BOOL:
  case TYPE_INT:
    sprintf(result, "%d", (int) val->val.int_val); return result;

  case TYPE_COUNT:
  case TYPE_COUNTER:
    sprintf(result, "%d", (int) val->val.uint_val); return result;
    
  case TYPE_PORT:
    sprintf(result, "%d", (int) val->val.port_val.port); return result;

  case TYPE_SUBNET:
    sprintf(result, "\"%s\"", Render(val->val.subnet_val).c_str()); return result;
    
  case TYPE_ADDR:
    sprintf(result, "\"%s\"", Render(val->val.addr_val).c_str()); return result;

  case TYPE_INTERVAL:
  case TYPE_TIME:	
    sprintf(result, "%"PRIu64"", (uint64) (val->val.double_val * 1000)); return result;
  case TYPE_DOUBLE:
    sprintf(result, "%s", Render(val->val.double_val).c_str()); return result;

  case TYPE_ENUM:
  case TYPE_STRING:
  case TYPE_FILE:
  case TYPE_FUNC:
    {
      int size = val->val.string_val->size();
      const char* data = val->val.string_val->data();
      
      if ( ! size )
	return 0;
      sprintf(result, "\"%s\"", data); return result;
    }

  case TYPE_TABLE:
    {
      char* tmp = new char[MAX_EVENT_SIZE];
      int tmp_offset = 0;
      strcpy(tmp, "{");
      tmp_offset = 1;
      bool result_seen = false;
      for ( int j = 0; j < val->val.set_val.size; j++ )
	{
	  char* sub_field = FieldToString(val->val.set_val.vals[j], field);
	  if ( sub_field ){
	    
	    if ( result_seen ){
	      strcpy(tmp + tmp_offset, ",");
	      tmp_offset += 1;
	    }
	    else
	      result_seen = true;
	    
	    sprintf(tmp + tmp_offset, "\"%s\":%s", field->name.c_str(), sub_field);
	    tmp_offset = strlen(tmp);
	  }
	}
      strcpy(tmp + tmp_offset, "}");
      tmp_offset += 1;
      sprintf(result, "%s", tmp); 
      return result;
    }
    
  case TYPE_VECTOR:
    {
      char* tmp = new char[MAX_EVENT_SIZE];
      int tmp_offset = 0;
      strcpy(tmp, "{");
      tmp_offset = 1;
      bool result_seen = false;
      for ( int j = 0; j < val->val.vector_val.size; j++ )
	{
	  char* sub_field = FieldToString(val->val.vector_val.vals[j], field);
	  if ( sub_field ){
	    
	    if ( result_seen ){
	      strcpy(tmp + tmp_offset, ",");
	      tmp_offset += 1;
	    }
	    else
	      result_seen = true;
	    
	    sprintf(tmp + tmp_offset, "\"%s\":%s", field->name.c_str(), sub_field);
	    tmp_offset = strlen(tmp);
	  }
	}
      strcpy(tmp + tmp_offset, "}");
      tmp_offset += 1;
      sprintf(result, "%s", tmp); 
      return result;
    }

  default:
    {
      return (char *)"{}";
    }

  }

}

char* ElasticSearch::AddFieldToBuffer(Value* val, const Field* field)
	{
    	if ( ! val->present )
	  return 0;
	
	char* result = new char[MAX_EVENT_SIZE];
	sprintf(result, "\"%s\":%s", field->name.c_str(), FieldToString(val, field));
	return result;

	}

bool ElasticSearch::DoWrite(int num_fields, const Field* const * fields,
			     Value** vals)
	{
	  // Our action line looks like:
	  //   {"index":{"_index":"$index_name","_type":"$type_prefix$path"}}\n{
	  
	  bool resultSeen = false;

	  for ( int i = 0; i < num_fields; i++ )
		{
		char* result = AddFieldToBuffer(vals[i], fields[i]);
		if ( result ) {
		  if ( ! resultSeen ) {
		    current_offset += sprintf(buffer + current_offset, "{\"index\":{\"_index\":\"%s\",\"_type\":\"%s%s\"}\n{", index_name, type_prefix, Path().c_str());
		    resultSeen = true;
		  }
		  else {
		    strcat(buffer, ",");
		    current_offset += 1;
		  }
		  strcat(buffer, result);
		  current_offset += strlen(result);
		}
	      }

	  if ( resultSeen ) {
	    strcat(buffer, "}\n");
	    current_offset += 2;
	    counter += 1;
	    if ( counter >= batch_size ){
	      BatchIndex();
	      current_offset = 0;
	      buffer[current_offset] = 0;
	      counter = 0;
	    }
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

// HTTP Functions start here.

CURL* ElasticSearch::HTTPSetup()
{
  char URL[2048];
  CURL* handle;
  struct curl_slist *headers=NULL;
  
  handle = curl_easy_init();
  if ( ! handle )
    return handle;
  
  sprintf(URL, "http://%s:%d/_bulk", server_host, (int) server_port);
  curl_easy_setopt(handle, CURLOPT_URL, URL);

  headers = curl_slist_append(NULL, "Content-Type: text/json; charset=utf-8");
  curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);

  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, &logging::writer::ElasticSearch::HTTPReceive); // This gets called with the result.
  curl_easy_setopt(handle, CURLOPT_POST, 1); // All requests are POSTs

  // HTTP 1.1 likes to use chunked encoded transfers, which aren't good for speed. The best (only?) way to disable that is to
  // just use HTTP 1.0
  curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
  return handle;
  
}

bool ElasticSearch::HTTPReceive(void* ptr, int size, int nmemb, void* userdata){
  //TODO: Do some verification on the result?
  return true;
}

bool ElasticSearch::HTTPSend(){
  CURLcode return_code;
  
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, curl_result);
  curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, buffer);
  curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, current_offset);
  
  return_code = curl_easy_perform(curl_handle);
  switch(return_code) {
  case CURLE_COULDNT_CONNECT:
  case CURLE_COULDNT_RESOLVE_HOST:
  case CURLE_WRITE_ERROR:
    return false;
  default:
    return true;
  }
}

#endif
