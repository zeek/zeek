// See the file "COPYING" in the main distribution directory for copyright.
//
// A binary log writer producing DataSeries output. See doc/data-series.rst
// for more information.

#ifndef LOGGING_WRITER_DATA_SERIES_H
#define LOGGING_WRITER_DATA_SERIES_H

#include <DataSeries/ExtentType.hpp>
#include <DataSeries/DataSeriesFile.hpp>
#include <DataSeries/DataSeriesModule.hpp>
#include <DataSeries/GeneralField.hpp>

#include "../WriterBackend.h"
#include "threading/formatters/Ascii.h"

namespace logging { namespace writer {

class DataSeries : public WriterBackend {
public:
	DataSeries(WriterFrontend* frontend);
	~DataSeries();

	static WriterBackend* Instantiate(WriterFrontend* frontend)
		{ return new DataSeries(frontend); }

protected:
	// Overidden from WriterBackend.

	virtual bool DoInit(const WriterInfo& info, int num_fields,
			    const threading::Field* const * fields);

	virtual bool DoWrite(int num_fields, const threading::Field* const* fields,
			     threading::Value** vals);
	virtual bool DoSetBuf(bool enabled);
	virtual bool DoRotate(const char* rotated_path, double open,
			      double close, bool terminating);
	virtual bool DoFlush(double network_time);
	virtual bool DoFinish(double network_time);
	virtual bool DoHeartbeat(double network_time, double current_time);

private:
	static const size_t ROW_MIN = 2048;			// Minimum extent size.
	static const size_t ROW_MAX = (1024 * 1024 * 100);	// Maximum extent size.
	static const size_t THREAD_MIN = 1;			// Minimum number of compression threads that DataSeries may spawn.
	static const size_t THREAD_MAX = 128;			// Maximum number of compression threads that DataSeries may spawn.
	static const size_t TIME_SCALE = 1000000;		// Fixed-point multiplier for time values when converted to integers.
	const char* TIME_UNIT() { return "microseconds"; }      // DS name for time resolution when converted to integers. Must match TIME_SCALE.

	struct SchemaValue
		{
		string ds_type;
		string bro_type;
		string field_name;
		string field_options;
		};

	/**
	 *  Turns a log value into a std::string.  Uses an ostringstream to do the
	 *  heavy lifting, but still need to switch on the type to know which value
	 *  in the union to give to the string string for processing.
	 *
	 *  @param val The value we wish to convert to a string
	 *  @return the string value of val
	 */
	std::string LogValueToString(threading::Value *val);

	/**
	 *  Takes a field type and converts it to a relevant DataSeries type.
	 *
	 *  @param field We extract the type from this and convert it into a relevant DS type.
	 *  @return String representation of type that DataSeries can understand.
	 */
	string GetDSFieldType(const threading::Field *field);

	/**
	 *  Are there any options we should put into the XML schema?
	 *
	 *  @param field We extract the type from this and return any options that make sense for that type.
	 *  @return Options that can be added directly to the XML (e.g. "pack_relative=\"yes\"")
	 */
	std::string GetDSOptionsForType(const threading::Field *field);

	/**
	 *  Takes a list of types, a list of names, and a title, and uses it to construct a valid DataSeries XML schema
	 *  thing, which is then returned as a std::string
	 *
	 *  @param opts std::vector of strings containing a list of options to be appended to each field (e.g. "pack_relative=yes")
	 *  @param sTitle Name of this schema.  Ideally, these schemas would be aggregated and re-used.
	 */
	string BuildDSSchemaFromFieldTypes(const vector<SchemaValue>& vals, string sTitle);

	/** Closes the currently open file. */
	void CloseLog();

	/** Opens a new file. */
	bool OpenLog(string path);

	typedef std::map<string, GeneralField *> ExtentMap;
	typedef ExtentMap::iterator ExtentIterator;

	// Internal DataSeries structures we need to keep track of.
	vector<SchemaValue> schema_list;
	ExtentTypeLibrary log_types;
	ExtentType::Ptr log_type;
	ExtentSeries log_series;
	ExtentMap extents;
	int compress_type;

	DataSeriesSink* log_file;
	OutputModule* log_output;

	// Options set from the script-level.
	uint64 ds_extent_size;
	uint64 ds_num_threads;
	string ds_compression;
	bool ds_dump_schema;
	bool ds_use_integer_for_time;
	string ds_set_separator;

	threading::formatter::Ascii* ascii;
};

}
}

#endif

