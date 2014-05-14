// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#ifdef USE_DATASERIES

#include <map>
#include <string>
#include <errno.h>

#include <DataSeries/GeneralField.hpp>

#include "NetVar.h"
#include "threading/SerialTypes.h"

#include "DataSeries.h"

using namespace logging;
using namespace writer;

std::string DataSeries::LogValueToString(threading::Value *val)
	{
	// In some cases, no value is attached.  If this is the case, return
	// an empty string.
	if( ! val->present )
		return "";

	switch(val->type) {
	case TYPE_BOOL:
		return (val->val.int_val ? "true" : "false");

	case TYPE_INT:
		{
		std::ostringstream ostr;
		ostr << val->val.int_val;
		return ostr.str();
		}

	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
		{
		std::ostringstream ostr;
		ostr << val->val.uint_val;
		return ostr.str();
		}

	case TYPE_SUBNET:
		return ascii->Render(val->val.subnet_val);

	case TYPE_ADDR:
		return ascii->Render(val->val.addr_val);

	// Note: These two cases are relatively special.  We need to convert
	// these values into their integer equivalents to maximize precision.
	// At the moment, there won't be a noticeable effect (Bro uses the
	// double format everywhere internally, so we've already lost the
	// precision we'd gain here), but timestamps may eventually switch to
	// this representation within Bro.
	//
	// In the near-term, this *should* lead to better pack_relative (and
	// thus smaller output files).
	case TYPE_TIME:
	case TYPE_INTERVAL:
		if ( ds_use_integer_for_time )
			{
			std::ostringstream ostr;
			ostr << (uint64_t)(DataSeries::TIME_SCALE * val->val.double_val);
			return ostr.str();
			}
		else
			return ascii->Render(val->val.double_val);

	case TYPE_DOUBLE:
		return ascii->Render(val->val.double_val);

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		if ( ! val->val.string_val.length )
			return "";

		return string(val->val.string_val.data, val->val.string_val.length);

	case TYPE_TABLE:
		{
		if ( ! val->val.set_val.size )
			return "";

		string tmpString = "";

		for ( int j = 0; j < val->val.set_val.size; j++ )
			{
			if ( j > 0 )
				tmpString += ds_set_separator;

			tmpString += LogValueToString(val->val.set_val.vals[j]);
			}

		return tmpString;
		}

	case TYPE_VECTOR:
		{
		if ( ! val->val.vector_val.size )
			return "";

		string tmpString = "";

		for ( int j = 0; j < val->val.vector_val.size; j++ )
			{
			if ( j > 0 )
				tmpString += ds_set_separator;

			tmpString += LogValueToString(val->val.vector_val.vals[j]);
			}

		return tmpString;
		}

	default:
		InternalError(Fmt("unknown type %s in DataSeries::LogValueToString", type_name(val->type)));
		return "cannot be reached";
	}
}

string DataSeries::GetDSFieldType(const threading::Field *field)
{
	switch(field->type) {
	case TYPE_BOOL:
		return "bool";

	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
	case TYPE_INT:
		return "int64";

	case TYPE_DOUBLE:
		return "double";

	case TYPE_TIME:
	case TYPE_INTERVAL:
		return ds_use_integer_for_time ? "int64" : "double";

	case TYPE_SUBNET:
	case TYPE_ADDR:
	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_TABLE:
	case TYPE_VECTOR:
	case TYPE_FUNC:
		return "variable32";

	default:
		InternalError(Fmt("unknown type %s in DataSeries::GetDSFieldType", type_name(field->type)));
		return "cannot be reached";
	}
}

string DataSeries::BuildDSSchemaFromFieldTypes(const vector<SchemaValue>& vals, string sTitle)
	{
	if( ! sTitle.size() )
		sTitle = "GenericBroStream";

	string xmlschema = "<ExtentType name=\""
		+ sTitle
		+ "\" version=\"1.0\" namespace=\"bro.org\">\n";

	for( size_t i = 0; i < vals.size(); ++i )
		{
		xmlschema += "\t<field type=\""
			+ vals[i].ds_type
			+ "\" name=\""
			+ vals[i].field_name
			+ "\" " + vals[i].field_options
			+ "/>\n";
		}

	xmlschema += "</ExtentType>\n";

	for( size_t i = 0; i < vals.size(); ++i )
		{
		xmlschema += "<!-- " + vals[i].field_name
			+ " : " + vals[i].bro_type
			+ " -->\n";
		}

	return xmlschema;
}

std::string DataSeries::GetDSOptionsForType(const threading::Field *field)
{
	switch( field->type ) {
	case TYPE_TIME:
	case TYPE_INTERVAL:
		{
		std::string s;
		s += "pack_relative=\"" + std::string(field->name) + "\"";

		if ( ! ds_use_integer_for_time )
			s += " pack_scale=\"1e-6\" print_format=\"%.6f\" pack_scale_warn=\"no\"";
		else
			s += string(" units=\"") + TIME_UNIT() + "\" epoch=\"unix\"";

		return s;
		}

	case TYPE_SUBNET:
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

DataSeries::DataSeries(WriterFrontend* frontend) : WriterBackend(frontend)
{
	ds_compression = string((const char *)BifConst::LogDataSeries::compression->Bytes(),
				BifConst::LogDataSeries::compression->Len());
	ds_dump_schema = BifConst::LogDataSeries::dump_schema;
	ds_extent_size = BifConst::LogDataSeries::extent_size;
	ds_num_threads = BifConst::LogDataSeries::num_threads;
	ds_use_integer_for_time = BifConst::LogDataSeries::use_integer_for_time;
	ds_set_separator = ",";

	threading::formatter::Ascii::SeparatorInfo sep_info;
	ascii = new threading::formatter::Ascii(this, sep_info);

	compress_type = Extent::compress_none;
	log_file = 0;
	log_output = 0;
}

DataSeries::~DataSeries()
	{
	delete ascii;
	}

bool DataSeries::OpenLog(string path)
	{
	log_file = new DataSeriesSink(path + ".ds", compress_type);
	log_file->writeExtentLibrary(log_types);

	for( size_t i = 0; i < schema_list.size(); ++i )
		{
		string fn = schema_list[i].field_name;
		GeneralField* gf = 0;
#ifdef USE_PERFTOOLS_DEBUG
		{
		// GeneralField isn't cleaning up some results of xml parsing, reported
		// here: https://github.com/dataseries/DataSeries/issues/1
		// Ignore for now to make leak tests pass.  There's confidence that
		// we do clean up the GeneralField* since the ExtentSeries dtor for
		// member log_series would trigger an assert if dynamically allocated
		// fields aren't deleted beforehand.
		HeapLeakChecker::Disabler disabler;
#endif
		gf = GeneralField::create(log_series, fn);
#ifdef USE_PERFTOOLS_DEBUG
		}
#endif
		extents.insert(std::make_pair(fn, gf));
		}

	if ( ds_extent_size < ROW_MIN )
		{
		Warning(Fmt("%d is not a valid value for 'rows'. Using min of %d instead", (int)ds_extent_size, (int)ROW_MIN));
		ds_extent_size = ROW_MIN;
		}

	else if( ds_extent_size > ROW_MAX )
		{
		Warning(Fmt("%d is not a valid value for 'rows'.  Using max of %d instead", (int)ds_extent_size, (int)ROW_MAX));
		ds_extent_size = ROW_MAX;
		}

	log_output = new OutputModule(*log_file, log_series, log_type, ds_extent_size);

	return true;
	}

bool DataSeries::DoInit(const WriterInfo& info, int num_fields, const threading::Field* const * fields)
	{
	// We first construct an XML schema thing (and, if ds_dump_schema is
	// set, dump it to path + ".ds.xml").  Assuming that goes well, we
	// use that schema to build our output logfile and prepare it to be
	// written to.

	// Note: compressor count must be set *BEFORE* DataSeriesSink is
	// instantiated.
	if( ds_num_threads < THREAD_MIN && ds_num_threads != 0 )
		{
		Warning(Fmt("%d is too few threads!  Using %d instead", (int)ds_num_threads, (int)THREAD_MIN));
		ds_num_threads = THREAD_MIN;
		}

	if( ds_num_threads > THREAD_MAX )
		{
		Warning(Fmt("%d is too many threads!  Dropping back to %d", (int)ds_num_threads, (int)THREAD_MAX));
		ds_num_threads = THREAD_MAX;
		}

	if( ds_num_threads > 0 )
		DataSeriesSink::setCompressorCount(ds_num_threads);

	for ( int i = 0; i < num_fields; i++ )
		{
		const threading::Field* field = fields[i];
		SchemaValue val;
		val.ds_type = GetDSFieldType(field);
		val.field_name = string(field->name);
		val.field_options = GetDSOptionsForType(field);
		val.bro_type = field->TypeName();
		schema_list.push_back(val);
		}

	string schema = BuildDSSchemaFromFieldTypes(schema_list, info.path);

	if( ds_dump_schema )
		{
		string name = string(info.path) + ".ds.xml";
		FILE* pFile = fopen(name.c_str(), "wb" );

		if( pFile )
			{
			fwrite(schema.c_str(), 1, schema.length(), pFile);
			fclose(pFile);
			}

		else
			Error(Fmt("cannot dump schema: %s", Strerror(errno)));
		}

	compress_type = Extent::compress_all;

	if( ds_compression == "lzf" )
		compress_type = Extent::compress_lzf;

	else if( ds_compression == "lzo" )
		compress_type = Extent::compress_lzo;

	else if( ds_compression == "gz" )
		compress_type = Extent::compress_gz;

	else if( ds_compression == "bz2" )
		compress_type = Extent::compress_bz2;

	else if( ds_compression == "none" )
		compress_type = Extent::compress_none;

	else if( ds_compression == "any" )
		compress_type = Extent::compress_all;

	else
		Warning(Fmt("%s is not a valid compression type. Valid types are: 'lzf', 'lzo', 'gz', 'bz2', 'none', 'any'. Defaulting to 'any'", ds_compression.c_str()));

        log_type = log_types.registerTypePtr(schema);
	log_series.setType(log_type);

	return OpenLog(info.path);
	}

bool DataSeries::DoFlush(double network_time)
{
	// Flushing is handled by DataSeries automatically, so this function
	// doesn't do anything.
	return true;
}

void DataSeries::CloseLog()
	{
	for( ExtentIterator iter = extents.begin(); iter != extents.end(); ++iter )
		delete iter->second;

	extents.clear();

	// Don't delete the file before you delete the output, or bad things
	// will happen.
	delete log_output;
	delete log_file;

	log_output = 0;
	log_file = 0;
	}

bool DataSeries::DoFinish(double network_time)
{
	CloseLog();
	return true;
}

bool DataSeries::DoWrite(int num_fields, const threading::Field* const * fields,
			 threading::Value** vals)
{
	log_output->newRecord();

	for( size_t i = 0; i < (size_t)num_fields; ++i )
		{
		ExtentIterator iter = extents.find(fields[i]->name);
		assert(iter != extents.end());

		if( iter != extents.end() )
			{
			GeneralField *cField = iter->second;

			if( vals[i]->present )
				cField->set(LogValueToString(vals[i]));
			}
		}

	return true;
}

bool DataSeries::DoRotate(const char* rotated_path, double open, double close, bool terminating)
{
	// Note that if DS files are rotated too often, the aggregate log
	// size will be (much) larger.
	CloseLog();

	string dsname = string(Info().path) + ".ds";
	string nname = string(rotated_path) + ".ds";

	if ( rename(dsname.c_str(), nname.c_str()) != 0 )
		{
		char buf[256];
		strerror_r(errno, buf, sizeof(buf));
		Error(Fmt("failed to rename %s to %s: %s", dsname.c_str(),
				  nname.c_str(), buf));
		FinishedRotation();
		return false;
		}

	if ( ! FinishedRotation(nname.c_str(), dsname.c_str(), open, close, terminating) )
		{
		Error(Fmt("error rotating %s to %s", dsname.c_str(), nname.c_str()));
		return false;
		}

	return OpenLog(Info().path);
}

bool DataSeries::DoSetBuf(bool enabled)
{
	// DataSeries is *always* buffered to some degree.  This option is ignored.
	return true;
}

bool DataSeries::DoHeartbeat(double network_time, double current_time)
{
	return true;
}

#endif /* USE_DATASERIES */
