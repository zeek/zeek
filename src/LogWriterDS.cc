// See the file "COPYING" in the main distribution directory for copyright.

#include <map>
#include <string>
#include <errno.h>

#include "LogWriterDS.h"
#include "NetVar.h"

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
		ostr << dotted_addr(val->val.subnet_val.net);
		ostr << "/";
		ostr << val->val.subnet_val.width;
		return ostr.str();

	case TYPE_NET:
	case TYPE_ADDR:
		ostr << dotted_addr(val->val.addr_val);
		return ostr.str();

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
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
	/*
	// These types are terrifying.  I'll get to them later.
	case TYPE_TABLE:
	{
		if ( ! val->val.set_val.size )
			{
			desc->AddN(empty_field, empty_field_len);
			break;
			}

		for ( int j = 0; j < val->val.set_val.size; j++ )
			{
			if ( j > 0 )
				desc->AddN(set_separator, set_separator_len);

			if ( ! DoWriteOne(desc, val->val.set_val.vals[j], field) )
				return false;
	}

		break;
		}

	case TYPE_VECTOR:
		{
		if ( ! val->val.vector_val.size )
			{
			desc->AddN(empty_field, empty_field_len);
			break;
			}

		for ( int j = 0; j < val->val.vector_val.size; j++ )
			{
			if ( j > 0 )
				desc->AddN(set_separator, set_separator_len);

			if ( ! DoWriteOne(desc, val->val.vector_val.vals[j], field) )
				return false;
			}

		break;
		}
	*/
	default:
		return "???";
	}
}

/**
 *  Turns script variables into a form our logger can use.
 */
LogWriterDS::LogWriterDS()
{
	ds_compression = string((const char *)BifConst::LogDataSeries::ds_compression->Bytes(), BifConst::LogDataSeries::ds_compression->Len());
	ds_dump_schema = BifConst::LogDataSeries::ds_dump_schema;
	ds_extent_rows = BifConst::LogDataSeries::ds_extent_rows;
}

/**
 *  After a long, tiring battle in the war for network domination, our LogWriterDS will be retired.  Rest well, dude; you've earned it.
 *
 *  Destroys the LogWriter, and cleans up any memory allocated to it.
 */
LogWriterDS::~LogWriterDS()
{
	fprintf(stderr, "Welcome to the destructor!\n");
	for(ExtentIterator iter = extents.begin();
		iter != extents.end(); ++iter)
		{
		delete iter->second;
		}
	extents.clear();
	// Don't delete the file before you delete the output, or bad things happen.
	// ASK ME HOW I KNOW!  *insane laughter*
	delete log_output;
	delete log_file;
}

/**
 *  Takes a field type and converts it to a relevant DataSeries type.
 *
 *  Note that the table / vector entries are tricky, and are going to be revisited later.
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
		return "int64";

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
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
 *  @param sTitle Name of this schema.  Ideally, these schemas would be aggregated and re-used.
 */
static string _BuildDSSchemaFromFieldTypes(const vector<string> types, const vector<string> names, string sTitle)
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
			xmlschema += "\t<field type=\"" + types[i] + "\" name=\"" + names[i] + "\" pack_unique=\"yes\" />\n";
			}
		else
			{
			xmlschema += "\t<field type=\"" + types[i] + "\" name=\"" + names[i] + "\" />\n";
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
	vector<string> typevec;
	vector<string> namevec;
	for ( int i = 0; i < num_fields; i++ )
		{
		const LogField* field = fields[i];
		typevec.push_back(_GetDSFieldType(field).c_str());
		namevec.push_back(field->name);
		}
	string schema = _BuildDSSchemaFromFieldTypes(typevec, namevec, path);
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
	
    log_types;
    log_type = const_cast<ExtentType *>(log_types.registerType(schema));

	log_series.setType(*log_type);
    log_file = new DataSeriesSink(path + ".ds");
    log_file->writeExtentLibrary(log_types);
	
	for(size_t i = 0; i < typevec.size(); ++i)
		extents.insert(std::make_pair(namevec[i], GeneralField::create(log_series, namevec[i])));

    log_output = new OutputModule(*log_file, log_series, log_type, 1024);

	fprintf(stderr, "%s opened.  Let's rock!\n", string(path + ".ds").c_str());

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
	fprintf(stderr, "Welcome to the finish!\n");
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
	for(int i = 0; i < num_fields; ++i)
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
 *  Still trying to figure out what this is supposed to do.
 *  TODO: Make this work.  Somehow.
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
static LogWriterRegistrar __register_logger(BifEnum::Log::WRITER_DATASERIES, "DataSeries", LogWriterDS::Instantiate);

