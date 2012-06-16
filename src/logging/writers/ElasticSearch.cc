// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#ifdef INSTALL_ELASTICSEARCH

#include <string>
#include <errno.h>

#include "util.h"
#include "BroString.h"

#include "NetVar.h"
#include "threading/SerialTypes.h"

#include <curl/curl.h>
#include <curl/easy.h>

#include "ElasticSearch.h"

using namespace logging;
using namespace writer;
using threading::Value;
using threading::Field;

ElasticSearch::ElasticSearch(WriterFrontend* frontend) : WriterBackend(frontend)
	{
	cluster_name_len = BifConst::LogElasticSearch::cluster_name->Len();
	cluster_name = new char[cluster_name_len + 1];
	memcpy(cluster_name, BifConst::LogElasticSearch::cluster_name->Bytes(), cluster_name_len);
	cluster_name[cluster_name_len] = 0;
	
	buffer.Clear();
	counter = 0;
	last_send = current_time();
	
	curl_handle = HTTPSetup();
	curl_result = new char[1024];
	}

ElasticSearch::~ElasticSearch()
	{
	delete [] cluster_name;
	}

bool ElasticSearch::DoInit(string path, int num_fields, const Field* const * fields)
	{
	//TODO: Determine what, if anything, needs to be done here.
	return true;
	}

bool ElasticSearch::DoFlush()
	{
	return true;
	}

bool ElasticSearch::DoFinish()
	{
	BatchIndex();
	return WriterBackend::DoFinish();
	}
	
bool ElasticSearch::BatchIndex()
	{
	HTTPSend();
	buffer.Clear();
	counter = 0;
	last_send = current_time();
	return true;
	}

bool ElasticSearch::AddFieldValueToBuffer(Value* val, const Field* field)
	{
	switch ( val->type ) 
		{
		// ES treats 0 as false and any other value as true so bool types go here.
		case TYPE_BOOL:
		case TYPE_INT:
			buffer.Add(val->val.int_val);
			break;
		
		case TYPE_COUNT:
		case TYPE_COUNTER:
			buffer.Add(val->val.uint_val);
			break;
		
		case TYPE_PORT:
			buffer.Add(val->val.port_val.port);
			break;
		
		case TYPE_SUBNET:
			buffer.AddRaw("\"", 1);
			buffer.Add(Render(val->val.subnet_val));
			buffer.AddRaw("\"", 1);
			break;
		
		case TYPE_ADDR:
			buffer.AddRaw("\"", 1);
			buffer.Add(Render(val->val.addr_val));
			buffer.AddRaw("\"", 1);
			break;
		
		case TYPE_DOUBLE:
			buffer.Add(val->val.double_val);
			break;
		
		case TYPE_INTERVAL:
		case TYPE_TIME:
			// ElasticSearch uses milliseconds for timestamps
			buffer.Add((uint64_t) (val->val.double_val * 1000));
			break;
		
		case TYPE_ENUM:
		case TYPE_STRING:
		case TYPE_FILE:
		case TYPE_FUNC:
			{
			buffer.AddRaw("\"", 1);
			for ( uint i = 0; i < val->val.string_val->size(); ++i )
				{
				char c = val->val.string_val->data()[i];
				// HTML entity encode special characters.
				if ( c < 32 || c > 126 || c == '\n' || c == '"' || c == '\'' || c == '\\' || c == '&' )
					{
					static const char hex_chars[] = "0123456789abcdef";
					buffer.AddRaw("\\u00", 4);
					buffer.AddRaw(&hex_chars[(c & 0xf0) >> 4], 1);
					buffer.AddRaw(&hex_chars[c & 0x0f], 1);
					//buffer.AddRaw("&#//", 2);
					//buffer.Add((uint8_t) c);
					//buffer.AddRaw(";", 1);
					}
				else
					buffer.AddRaw(&c, 1);
				}
			buffer.AddRaw("\"", 1);
			break;
			}
		
		case TYPE_TABLE:
			{
			buffer.AddRaw("[", 1);
			for ( int j = 0; j < val->val.set_val.size; j++ )
				{
				if ( j > 0 )
					buffer.AddRaw(",", 1);
				AddFieldValueToBuffer(val->val.set_val.vals[j], field);
				}
			buffer.AddRaw("]", 1);
			break;
			}
			
		case TYPE_VECTOR:
			{
			buffer.AddRaw("[", 1);
			for ( int j = 0; j < val->val.vector_val.size; j++ )
				{
				if ( j > 0 )
					buffer.AddRaw(",", 1);
				AddFieldValueToBuffer(val->val.vector_val.vals[j], field);
				}
			buffer.AddRaw("]", 1);
			break;
			}
		
		default:
			return false;
		}
	return true;
	}

bool ElasticSearch::AddFieldToBuffer(Value* val, const Field* field)
	{
	if ( ! val->present )
		return false;
	
	buffer.AddRaw("\"", 1);
	buffer.Add(field->name);
	buffer.AddRaw("\":", 2);
	AddFieldValueToBuffer(val, field);
	return true;
	}

bool ElasticSearch::DoWrite(int num_fields, const Field* const * fields,
			     Value** vals)
	{
	// Our action line looks like:
	//   {"index":{"_index":"$index_name","_type":"$type_prefix$path"}}\n
	if ( counter == 0 )
		{
		buffer.AddRaw("{\"index\":{\"_index\":\"", 20);
		buffer.AddN((const char*) BifConst::LogElasticSearch::index_name->Bytes(),
		            BifConst::LogElasticSearch::index_name->Len());
		buffer.AddRaw("\",\"_type\":\"", 11);
		buffer.AddN((const char*) BifConst::LogElasticSearch::type_prefix->Bytes(),
		            BifConst::LogElasticSearch::type_prefix->Len());
		buffer.Add(Path());
		buffer.AddRaw("\"}\n", 3);
		}
	
	for ( int i = 0; i < num_fields; i++ )
		{
		if ( i == 0 )
			buffer.AddRaw("{", 1);
		else if ( buffer.Bytes()[buffer.Len()] != ',' && vals[i]->present )
			buffer.AddRaw(",", 1);
		AddFieldToBuffer(vals[i], fields[i]);
		}
		
	buffer.AddRaw("}\n", 2);
	
	counter++;
	if ( counter >= BifConst::LogElasticSearch::batch_size )
		BatchIndex();
	
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

bool ElasticSearch::DoHeartbeat(double network_time, double current_time)
	{
	if ( last_send > 0 &&
	     current_time-last_send > BifConst::LogElasticSearch::max_batch_interval )
		{
		BatchIndex();
		}
	
	return true;
	}


// HTTP Functions start here.

CURL* ElasticSearch::HTTPSetup()
	{
	const char *URL = fmt("http://%s:%d/_bulk", BifConst::LogElasticSearch::server_host->CheckString(),
	                                            (int) BifConst::LogElasticSearch::server_port);;
	CURL* handle;
	struct curl_slist *headers=NULL;
	
	handle = curl_easy_init();
	if ( ! handle )
		return handle;
	
	//sprintf(URL, "http://%s:%d/_bulk", BifConst::LogElasticSearch::server_host->CheckString(), (int) BifConst::LogElasticSearch::server_port);
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

bool ElasticSearch::HTTPReceive(void* ptr, int size, int nmemb, void* userdata)
	{
	//TODO: Do some verification on the result?
	return true;
	}

bool ElasticSearch::HTTPSend()
	{
	CURLcode return_code;
	
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, curl_result);
	curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, buffer.Bytes());
	curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, buffer.Len());
	
	return_code = curl_easy_perform(curl_handle);
	switch ( return_code ) 
		{
		case CURLE_COULDNT_CONNECT:
		case CURLE_COULDNT_RESOLVE_HOST:
		case CURLE_WRITE_ERROR:
			return false;
		
		default:
			return true;
		}
	}

#endif
