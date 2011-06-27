// See the file "COPYING" in the main distribution directory for copyright.

#include <map>
#include <string>
#include <errno.h>

#include "LogWriterDS.h"
#include "NetVar.h"

LogWriterDS::LogWriterDS()
{
	ds_compression = string((const char *)BifConst::LogDataSeries::ds_compression->Bytes(), BifConst::LogDataSeries::ds_compression->Len());
	ds_dump_schema = BifConst::LogDataSeries::ds_dump_schema;
	ds_extent_rows = BifConst::LogDataSeries::ds_extent_rows;
}

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

    log_file = new DataSeriesSink(path + ".ds");
    log_file->writeExtentLibrary(log_types);

    log_output = new OutputModule(*log_file, log_series, log_type, 1024);

	for(size_t i = 0; i < typevec.size(); ++i)
		{
		if(typevec[i] == "double")
    		extents.insert(std::make_pair(namevec[i], new DoubleField(log_series, namevec[i])));
		else if (typevec[i] == "variable32")
			extents.insert(std::make_pair(namevec[i], new Variable32Field(log_series, namevec[i])));
		else if(typevec[i] == "int64")
			extents.insert(std::make_pair(namevec[i], new Int64Field(log_series, namevec[i])));
		else if(typevec[i] == "bool")
			extents.insert(std::make_pair(namevec[i], new BoolField(log_series, namevec[i])));
		else
			fprintf(stderr, "Unsupported type: %s\n", typevec[i].c_str());
		}

	fprintf(stderr, "%s opened.  Let's rock!\n", string(path + ".ds").c_str());

	return true;

	}

bool LogWriterDS::DoFlush()
{
	return true;
}

void LogWriterDS::DoFinish()
{
	fprintf(stderr, "Welcome to the finish!\n");
}

bool LogWriterDS::DoWriteOne(ODesc* desc, LogVal* val, const LogField* field)
{
	/*
	switch ( val->type ) 
	{
	case TYPE_BOOL:
		desc->Add(val->val.int_val ? "T" : "F");
		break;

	case TYPE_INT:
		desc->Add(val->val.int_val);
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
		desc->Add(val->val.uint_val);
		break;

	case TYPE_SUBNET:
		desc->Add(dotted_addr(val->val.subnet_val.net));
		desc->Add("/");
		desc->Add(val->val.subnet_val.width);
		break;

	case TYPE_NET:
	case TYPE_ADDR:
		desc->Add(dotted_addr(val->val.addr_val));
		break;

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		desc->Add(val->val.double_val);
	break;

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	{
		int size = val->val.string_val->size();
		if ( size )
			desc->AddN(val->val.string_val->data(), val->val.string_val->size());
		else
			desc->AddN(empty_field, empty_field_len);
		break;
	}

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

	default:
		Error(Fmt("unsupported field format %d for %s", val->type,
			  field->name.c_str()));
		return false;
	}
	*/
	return true;
}

bool LogWriterDS::DoWrite(int num_fields, const LogField* const * fields,
			     LogVal** vals)
{
/*	ODesc desc(DESC_READABLE);
	desc.SetEscape(separator, separator_len);

	for ( int i = 0; i < num_fields; i++ )
		{
		if ( i > 0 )
			desc.AddRaw(separator, separator_len);

		if ( ! DoWriteOne(&desc, vals[i], fields[i]) )
			return false;
		}

	desc.AddRaw("\n", 1);

	if ( fwrite(desc.Bytes(), desc.Len(), 1, file) != 1 )
		{
		Error(Fmt("error writing to %s: %s", fname.c_str(), strerror(errno)));
		return false;
		}

	if ( IsBuf() )
		fflush(file);
*/
	return true;
}

bool LogWriterDS::DoRotate(string rotated_path, string postprocessor, double open,
			      double close, bool terminating)
{
	return true;
}

bool LogWriterDS::DoSetBuf(bool enabled)
{
	return true;
}

static LogWriterRegistrar __register_logger(BifEnum::Log::WRITER_DATASERIES, "DataSeries", LogWriterDS::Instantiate);


