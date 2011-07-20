// See the file "COPYING" in the main distribution directory for copyright.

#include <map>
#include <string>
#include <errno.h>

#include "LogWriterDS.h"
#include "NetVar.h"

namespace bro
{

// NOTE: Naming conventions are a little bit scattershot at the moment.  Within the scope of this file, a function name prefixed by '_' denotes a static function.

/**
 *  Turns a log value into a std::string.  Uses an ostringstream to do the heavy lifting, but still need to switch
 *  on the type to know which value in the union to give to the string string for processing.
 *
 *  @param val The value we wish to convert to a string
 *  @return the string value of val
 */
//TODO: Should I be using a SerializationFormat here and calling appropriate functions instead?  That somehow seems like overkill...
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
	// representation within Bro
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

/**
 * Builds an instance of the LogWriterDS
 */
LogWriter* LogWriterDS::Instantiate(bro::LogEmissary& parent, QueueInterface<MessageEvent *>& in_queue, QueueInterface<MessageEvent *>& out_queue)	
{ 
	return new LogWriterDS(parent, in_queue, out_queue); 
}

/**
 *  Turns script variables into a form our logger can use.
 */
LogWriterDS::LogWriterDS(bro::LogEmissary& parent, QueueInterface<MessageEvent *>& in_queue, QueueInterface<MessageEvent *>& out_queue)
: LogWriter(parent, in_queue, out_queue)
{
	ds_compression = string((const char *)BifConst::LogDataSeries::ds_compression->Bytes(), BifConst::LogDataSeries::ds_compression->Len());
	ds_dump_schema = BifConst::LogDataSeries::ds_dump_schema;
	ds_extent_rows = BifConst::LogDataSeries::ds_extent_rows;
	ds_num_threads = BifConst::LogDataSeries::ds_num_threads;
}

/**
 *  After a long, tiring battle in the war for network domination, our LogWriterDS will be retired.  Rest well, dude; you've earned it.
 *
 *  Destroys the LogWriter, and cleans up any memory allocated to it.
 */
LogWriterDS::~LogWriterDS()
{
}

/**
 *  Are there any options we should put into the XML schema?
 *
 *  @param field We extract the type from this and return any options that make sense for that type.
 *  @return Options that can be added directly to the XML (e.g. "pack_relative=\"yes\"")
 */
static std::string _GetDSOptionsForType(const LogField *field)
{
	switch(field->type)
	{
	case TYPE_TIME:
	case TYPE_INTERVAL:
		return "pack_relative=\"" + std::string(field->name) + "\"";
	default:
		return "";
	}
}

/**
 *  Takes a field type and converts it to a relevant DataSeries type.
 *
 *  @param field We extract the type from this and convert it into a relevant DS type.
 *  @return String representation of type that DataSeries can understand.
 */
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

/**
 *  Takes a list of types, a list of names, and a title, and uses it to construct a valid DataSeries XML schema
 *  thing, which is then returned as a std::string
 *
 *  @param types std::vector of strings containing DataSeries types (e.g. "int64", "variable32")
 *  @param names std::vector of strings containing a list of field names; used to name our DS fields
 *  @param opts std::vector of strings containing a list of options to be appended to each field (e.g. "pack_relative=yes")
 *  @param sTitle Name of this schema.  Ideally, these schemas would be aggregated and re-used.
 */
static string _BuildDSSchemaFromFieldTypes(const vector<string>& types, const vector<string>& names, const vector<string>& opts, string sTitle)
{
	if("" == sTitle)
		{
		sTitle = "GenericBroStream";
		}
    string xmlschema = "<ExtentType name=\"" + sTitle + "\" version=\"1.0\" namespace=\"bro-ids.org\">\n";
	for(size_t i = 0; i < types.size(); ++i)
		{
		if(types[i] == "variable32")
			{
			xmlschema += "\t<field type=\"" + types[i] + "\" name=\"" + names[i] + "\" " + opts[i] + " pack_unique=\"yes\" />\n";
			}
		else
			{
			xmlschema += "\t<field type=\"" + types[i] + "\" name=\"" + names[i] + "\" " + opts[i] + " />\n";
			}
		}
	xmlschema += "</ExtentType>\n";
	return xmlschema;
}

/**
 *  Takes a base path (*without* a file extension), a number of fields, and a list of those fields, and uses them
 *  to initialize an appropriate DataSeries output logfile.  To do this, we first construct an XML schema thing (and,
 *  if ds_dump_schema is set, dump it to path + ".ds.xml").  Assuming that goes well, we use that schema to build our
 *  output logfile and prepare it to be written to.
 *
 *  @param path Path to the logfile.  This function appends ".ds" to this value and tries to write there.
 *  @param num_fields The number of fields we're going to be logging (since fields is an old-school array)
 *  @param fields The fields themselves.  We pull types and names from these fields to create our schema.
 */

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
	vector<string> typevec;
	vector<string> namevec;
	vector<string> optvec;
	for ( int i = 0; i < num_fields; i++ )
		{
		const LogField* field = fields[i];
		typevec.push_back(_GetDSFieldType(field));
		namevec.push_back(field->name);
		optvec.push_back(_GetDSOptionsForType(field));
		}
	string schema = _BuildDSSchemaFromFieldTypes(typevec, namevec, optvec, path);
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
	
	for(size_t i = 0; i < typevec.size(); ++i)
		extents.insert(std::make_pair(namevec[i], GeneralField::create(log_series, namevec[i])));

	if(ds_extent_rows < ROW_MIN)
		{
			fprintf(stderr, "%d is not a valid value for 'rows'.  Using min of %d instead.\n", (int)ds_extent_rows, (int)ROW_MIN);
			ds_extent_rows = ROW_MIN;
		}
	else if(ds_extent_rows > ROW_MAX)
		{
			fprintf(stderr, "%d is not a valid value for 'rows'.  Using max of %d instead.\n", (int)ds_extent_rows, (int)ROW_MAX);
			ds_extent_rows = ROW_MAX;
		}
    log_output = new OutputModule(*log_file, log_series, log_type, ds_extent_rows);

	return true;

	}

/**
 * TODO: Make this do something useful!
 *
 * @return true if we flushed, false otherwise.
 */
bool LogWriterDS::DoFlush()
{
	return true;
}

/**
 *  Wrap up our files and write them out to disk.
 *
 *  In DataSeries' case, de-allocates relevant structures, which automatically calls flush code in their destructors.
 *
 *  TODO: Make Finish() work...
 */

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

/**
 *  Writes a new record into the DataSeries object thingy.
 *
 *  @param num_fields Number of fields in this record
 *  @param fields The list of fields (so we can do cool things like get field type, get field name, etc)
 *  @param vals The values we're trying to write to the log.  Ideally, fields[i]->type == vals[i]->type
 *  
 *  @return true if the record was written successfully.  DataSeries will abort() otherwise, so we don't bother returning false here ...
 */
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

/**
 *  Doesn't do anything for now. . . do we need to rotate this format?
 */
bool LogWriterDS::DoRotate(string rotated_path, string postprocessor, double open,
			      double close, bool terminating)
{
	return true;
}

/**
 *  DataSeries is *always* buffered to some degree.  This option is ignored.
 */
bool LogWriterDS::DoSetBuf(bool enabled)
{
	return true;
}

// Call our constructor in the global scope to register this logging type with the LogMgr.  This is used because
// certain logging types depend on optional libraries, and we feel like this is slightly cleaner than wrapping stuff 
// in #ifdef.
static LogWriterRegistrar __register_logger(BifEnum::Log::WRITER_DATASERIES, "DataSeries", NULL, LogWriterDS::Instantiate);

}

