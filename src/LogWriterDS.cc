// See the file "COPYING" in the main distribution directory for copyright.

#include <map>
#include <string>
#include <errno.h>

#include "LogWriterDS.h"
#include "NetVar.h"

// NOTE: Naming conventions are a little bit scattershot at the moment.  Within the scope of this file, a function name prefixed by '_' denotes a static function.

// ************************ LOCAL PROTOTYPES *********************************

struct SchemaValue;

/**
 *  Turns a log value into a std::string.  Uses an ostringstream to do the heavy lifting, but still need to switch
 *  on the type to know which value in the union to give to the string string for processing.
 *
 *  @param val The value we wish to convert to a string
 *  @return the string value of val
 */
static std::string _LogValueToString(LogVal *val);

/**
 *  Takes a field type and converts it to a relevant DataSeries type.
 *
 *  @param field We extract the type from this and convert it into a relevant DS type.
 *  @return String representation of type that DataSeries can understand.
 */
static string _GetDSFieldType(const LogField *field);

/**
 *  Takes a field type and converts it to a readable string.
 *
 *  @param field We extract the type from this and convert it into a readable string.
 *  @return String representation of the field's type
 */
static string _GetBroTypeString(const LogField *field);

/**
 *  Takes a list of types, a list of names, and a title, and uses it to construct a valid DataSeries XML schema
 *  thing, which is then returned as a std::string
 *
 *  @param opts std::vector of strings containing a list of options to be appended to each field (e.g. "pack_relative=yes")
 *  @param sTitle Name of this schema.  Ideally, these schemas would be aggregated and re-used.
 */
static string _BuildDSSchemaFromFieldTypes(const vector<SchemaValue>& vals, string sTitle);

/**
 *  Are there any options we should put into the XML schema?
 *
 *  @param field We extract the type from this and return any options that make sense for that type.
 *  @return Options that can be added directly to the XML (e.g. "pack_relative=\"yes\"")
 */
static std::string _GetDSOptionsForType(const LogField *field);

/**
 *  Internal helper structure; populate a vector of these which is passed to the XML generator for its use.
 */
struct SchemaValue
{
	string ds_type;
	string bro_type;
	string field_name;
	string field_options;

	SchemaValue(const LogField *field)
	{
		ds_type = _GetDSFieldType(field);
		field_name = string(field->name);
		field_options = _GetDSOptionsForType(field);
		bro_type = _GetBroTypeString(field);
	}
};

// ************************ LOCAL IMPL *********************************

static std::string _LogValueToString(LogVal *val)
{
	const int strsz = 1024;
	char strbuf[strsz];

	// In some cases, no value is attached.  If this is the case, return an empty string.
	if(!val->present)
		return "";
	
	std::ostringstream ostr;
	switch(val->type)
	{
	case TYPE_BOOL:
		return (val->val.int_val ? "true" : "false");

	case TYPE_INT:
		ostr << val->val.int_val;
		return ostr.str();

	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
		ostr << val->val.uint_val;
		return ostr.str();

	case TYPE_SUBNET:
		ostr << dotted_addr_r(val->val.subnet_val.net, strbuf, strsz);
		ostr << "/";
		ostr << val->val.subnet_val.width;
		return ostr.str();

	case TYPE_NET:
	case TYPE_ADDR:
		ostr << dotted_addr_r(val->val.addr_val, strbuf, strsz);
		return ostr.str();
	
	// Note: These two cases are relatively special.  We need to convert these values into their integer equivalents
	// to maximize precision.  At the moment, there won't be a noticeable effect (Bro uses the double format everywhere
	// internally, so we've already lost the precision we'd gain here), but timestamps may eventually switch to this
	// representation within Bro.
	//
	// in the near-term, this *should* lead to better pack_relative (and thus smaller output files).
	case TYPE_TIME:
	case TYPE_INTERVAL:
		ostr << (unsigned long)(LogWriterDS::TIME_SCALE * val->val.double_val);
		return ostr.str();

	case TYPE_DOUBLE:
		ostr << val->val.double_val;
		return ostr.str();

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	{
		int size = val->val.string_val->size();
		string tmpString = "";
		if(size)
			tmpString = string(val->val.string_val->data(), val->val.string_val->size());
		else
			tmpString = string("");
		return tmpString;
	}
	case TYPE_TABLE:
	{
		if ( ! val->val.set_val.size )
			{
			return "";
			}

		string tmpString = "";
		for ( int j = 0; j < val->val.set_val.size; j++ )
			{
			if ( j > 0 )
				tmpString += ":";  //TODO: Specify set separator char in configuration.

			tmpString += _LogValueToString(val->val.set_val.vals[j]);
			}
		return tmpString;
	}
	case TYPE_VECTOR:
	{
		if ( ! val->val.vector_val.size )
			{
			return "";
			}

		string tmpString = "";
		for ( int j = 0; j < val->val.vector_val.size; j++ )
			{
			if ( j > 0 )
				tmpString += ":";  //TODO: Specify set separator char in configuration.

			tmpString += _LogValueToString(val->val.vector_val.vals[j]);
			}

		return tmpString;
	}
	default:
		return "???";
	}
}

static string _GetDSFieldType(const LogField *field)
{
	switch(field->type)
	{
	case TYPE_BOOL:
		return "bool";

	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
	case TYPE_INT:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		return "int64";
	
	case TYPE_DOUBLE:
		return "double"; 

	case TYPE_SUBNET:
	case TYPE_NET:
	case TYPE_ADDR:
	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_TABLE:
	case TYPE_VECTOR:
	default:
		return "variable32";

	}
}

static string _GetBroTypeString(const LogField *field)
{
	switch(field->type)
	{
	case TYPE_BOOL:
		return "bool";
	case TYPE_COUNT:
		return "count";
	case TYPE_COUNTER:
		return "counter";
	case TYPE_PORT:
		return "port";
	case TYPE_INT:
		return "int";
	case TYPE_TIME:
		return "time";
	case TYPE_INTERVAL:
		return "interval";
	case TYPE_DOUBLE:
		return "double"; 
	case TYPE_SUBNET:
		return "subnet";
	case TYPE_NET:
		return "net";
	case TYPE_ADDR:
		return "addr";
	case TYPE_ENUM:
		return "enum";
	case TYPE_STRING:
		return "string";
	case TYPE_FILE:
		return "file";
	case TYPE_TABLE:
		return "table";
	case TYPE_VECTOR:
		return "vector";
	default:
		return "???";
	}
}

static string _BuildDSSchemaFromFieldTypes(const vector<SchemaValue>& vals, string sTitle)
{
	if("" == sTitle)
		{
		sTitle = "GenericBroStream";
		}
    string xmlschema;
	xmlschema  = "<ExtentType name=\"" + sTitle + "\" version=\"1.0\" namespace=\"bro-ids.org\">\n";
	for(size_t i = 0; i < vals.size(); ++i)
		{
		xmlschema += "\t<field type=\"" + vals[i].ds_type + "\" name=\"" + vals[i].field_name + "\" " + vals[i].field_options + "/>\n";
		}
	xmlschema += "</ExtentType>\n";
	for(size_t i = 0; i < vals.size(); ++i)
		{
		xmlschema += "<!--" + vals[i].field_name + "=" + vals[i].bro_type + "-->\n";
		}
	return xmlschema;
}

static std::string _GetDSOptionsForType(const LogField *field)
{
	switch(field->type)
	{
	case TYPE_TIME:
	case TYPE_INTERVAL:
		return "pack_relative=\"" + std::string(field->name) + "\"";
	case TYPE_SUBNET:
	case TYPE_NET:
	case TYPE_ADDR:
	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_TABLE:
	case TYPE_VECTOR:
		return "pack_unique=\"yes\"";
	default:
		return "";
	}
}

// ************************ CLASS IMPL *********************************

LogWriter* LogWriterDS::Instantiate(LogEmissary& parent, QueueInterface<MessageEvent *>& in_queue, QueueInterface<MessageEvent *>& out_queue)	
{ 
	return new LogWriterDS(parent, in_queue, out_queue); 
}

LogWriterDS::LogWriterDS(LogEmissary& parent, QueueInterface<MessageEvent *>& in_queue, QueueInterface<MessageEvent *>& out_queue)
: LogWriter(parent, in_queue, out_queue)
{
	ds_compression = string((const char *)BifConst::LogDataSeries::ds_compression->Bytes(), BifConst::LogDataSeries::ds_compression->Len());
	ds_dump_schema = BifConst::LogDataSeries::ds_dump_schema;
	ds_extent_size = BifConst::LogDataSeries::ds_extent_size;
	ds_num_threads = BifConst::LogDataSeries::ds_num_threads;
}

LogWriterDS::~LogWriterDS()
{
}

bool LogWriterDS::DoInit(string path, int num_fields,
			    const LogField* const * fields)
	{
	// Note: compressor count must be set *BEFORE* DataSeriesSink is instantiated.
	if(ds_num_threads < THREAD_MIN && ds_num_threads != 0)
		{
		fprintf(stderr, "%d is too few threads!  Using %d instead\n", (int)ds_num_threads, (int)THREAD_MIN);
		ds_num_threads = THREAD_MIN;
		}
	if(ds_num_threads > THREAD_MAX)
		{
		fprintf(stderr, "%d is too many threads!  Dropping back to %d\n", (int)ds_num_threads, (int)THREAD_MAX);
		ds_num_threads = THREAD_MAX;
		}
	
    if(ds_num_threads > 0)
		{
		DataSeriesSink::setCompressorCount(ds_num_threads);
		}
	vector<SchemaValue> schema_list;
	for ( int i = 0; i < num_fields; i++ )
		{
		const LogField* field = fields[i];
		SchemaValue val(field);
		schema_list.push_back(val);
		}
	string schema = _BuildDSSchemaFromFieldTypes(schema_list, path);
	if(ds_dump_schema)
		{
		FILE * pFile;
	  	pFile = fopen ( string(path + ".ds.xml").c_str() , "wb" );
	    if(NULL == pFile)
			{
			perror("Could not dump schema");
			}
		fwrite (schema.c_str(), 1 , schema.length() , pFile );
		fclose (pFile);
		}
	
	int compress_type = Extent::compress_all;
	
	if(ds_compression == "lzf")
		{
		compress_type = Extent::compress_lzf;
		}
	else if(ds_compression == "lzo")
		{
		compress_type = Extent::compress_lzo;
		}
	else if(ds_compression == "gz")
		{
		compress_type = Extent::compress_gz;
		}
	else if(ds_compression == "bz2")
		{
		compress_type = Extent::compress_bz2;
		}
	else if(ds_compression == "none")
		{
		compress_type = Extent::compress_none;
		}
	else if(ds_compression == "any")
		{
		compress_type = Extent::compress_all;
		}
	else
		{
		fprintf(stderr, "%s is not a valid compression type.  Valid types are: 'lzf', 'lzo', 'gz', 'bz2', 'none', 'any'\n", ds_compression.c_str());
		fprintf(stderr, "Defaulting to 'any'\n");
		}

    log_type = const_cast<ExtentType *>(log_types.registerType(schema));

	log_series.setType(*log_type);
    log_file = new DataSeriesSink(path + ".ds", compress_type);
	log_file->writeExtentLibrary(log_types);
	
	for(size_t i = 0; i < schema_list.size(); ++i)
		extents.insert(std::make_pair(schema_list[i].field_name, GeneralField::create(log_series, schema_list[i].field_name)));

	if(ds_extent_size < ROW_MIN)
		{
			fprintf(stderr, "%d is not a valid value for 'rows'.  Using min of %d instead.\n", (int)ds_extent_size, (int)ROW_MIN);
			ds_extent_size = ROW_MIN;
		}
	else if(ds_extent_size > ROW_MAX)
		{
			fprintf(stderr, "%d is not a valid value for 'rows'.  Using max of %d instead.\n", (int)ds_extent_size, (int)ROW_MAX);
			ds_extent_size = ROW_MAX;
		}
    log_output = new OutputModule(*log_file, log_series, log_type, ds_extent_size);

	return true;

	}

bool LogWriterDS::DoFlush()
{
	return true;
}

void LogWriterDS::DoFinish()
{
	for(ExtentIterator iter = extents.begin();
		iter != extents.end(); ++iter)
		{
		delete iter->second;
		}
	extents.clear();
	// Don't delete the file before you delete the output, or bad things happen.
	delete log_output;
	delete log_file;
}

bool LogWriterDS::DoWrite(int num_fields, const LogField* const * fields,
			     LogVal** vals)
{

	log_output->newRecord();
	for(size_t i = 0; i < (size_t)num_fields; ++i)
		{
		ExtentIterator iter = extents.find(fields[i]->name);
		assert(iter != extents.end());
		if( iter != extents.end() )
			{
			GeneralField *cField = iter->second;
			if(vals[i]->present)
				cField->set(_LogValueToString(vals[i]));
			}
		}

	return true;
}

bool LogWriterDS::DoRotate(string rotated_path, string postprocessor, double open,
			      double close, bool terminating)
{
	DoFinish();

	string nname = rotated_path + ".ds";
	rename(string(parent.Path() + ".ds").c_str(), nname.c_str());

	if ( postprocessor.size() &&
	     ! RunPostProcessor(nname, postprocessor, string(parent.Path() + ".ds").c_str(),
				open, close, terminating) )
		return false;

	return DoInit(parent.Path(), parent.NumFields(), parent.Fields());
}

bool LogWriterDS::DoSetBuf(bool enabled)
{
	return true;
}

// ************************ WRITER REGISTRATION *********************************

// Call our constructor in the global scope to register this logging type with the LogMgr.  This is used because
// certain logging types depend on optional libraries, and we feel like this is slightly cleaner than wrapping stuff 
// in #ifdef.
static LogWriterRegistrar __register_logger(BifEnum::Log::WRITER_DATASERIES, "DataSeries", NULL, LogWriterDS::Instantiate);

