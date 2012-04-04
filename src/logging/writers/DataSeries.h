// See the file "COPYING" in the main distribution directory for copyright.
//
// A binary log writer producing DataSeries output. See doc/data-series.rst
// for more information.

#ifndef LOGGING_WRITER_DATA_SERIES_H
#define LOGGING_WRITER_DATA_SERIES_H

#include "../WriterBackend.h"

#include <DataSeries/ExtentType.hpp>
#include <DataSeries/DataSeriesFile.hpp>
#include <DataSeries/DataSeriesModule.hpp>
#include <DataSeries/GeneralField.hpp>

namespace logging { namespace writer {

class DataSeries : public WriterBackend {
public:
	DataSeries(WriterFrontend* frontend);
	~DataSeries();

	static WriterBackend* Instantiate(WriterFrontend* frontend)
		{ return new DataSeries(frontend); }

protected:
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
	static const size_t ROW_MIN = 2048;                      // Minimum extent size.
	static const size_t ROW_MAX = (1024 * 1024 * 100);       // Maximum extent size.
	static const size_t THREAD_MIN = 1;                      // Minimum number of compression threads that DataSeries may spawn.
	static const size_t THREAD_MAX = 128;                    // Maximum number of compression threads that DataSeries may spawn.
	static const size_t TIME_SCALE = 1000000;                // Fixed-point multiplier for time values when converted to integers.

	std::string LogValueToString(threading::Value *val);

	typedef std::map<string, GeneralField *> ExtentMap;
	typedef ExtentMap::iterator ExtentIterator;

	// Internal DataSeries structures we need to keep track of.
	DataSeriesSink* log_file;
	ExtentTypeLibrary log_types;
	ExtentType *log_type;
	ExtentSeries log_series;
	OutputModule* log_output;
	ExtentMap extents;

	// Options set from the script-level.
	uint64 ds_extent_size;
	uint64 ds_num_threads;
	string ds_compression;
	bool ds_dump_schema;
};

}
}

#endif

