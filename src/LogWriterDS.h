// See the file "COPYING" in the main distribution directory for copyright.

#ifndef LOGWRITERDS_H
#define LOGWRITERDS_H

#include <DataSeries/ExtentType.hpp>
#include <DataSeries/GeneralField.hpp>
#include <DataSeries/DataSeriesFile.hpp>
#include <DataSeries/DataSeriesModule.hpp>
#include "LogWriter.h"

namespace bro
{

class LogWriterDS : public LogWriter {
public:
	LogWriterDS(bro::LogEmissary& parent, QueueInterface<MessageEvent *>& in_queue, QueueInterface<MessageEvent *>& out_queue);
	~LogWriterDS();

	static const size_t ROW_MIN = 2048;
	static const size_t ROW_MAX = (1024 * 1024 * 100);
	static const size_t THREAD_MIN = 1;
	static const size_t THREAD_MAX = 128;
	static const size_t TIME_SCALE = 1000000;   //TODO: I don't think this should be a configurable option in the LogWriterDS scope, but might be good for Bro in general...
	static LogWriter* Instantiate(LogEmissary& parent, QueueInterface<MessageEvent *>& in_queue, QueueInterface<MessageEvent *>& out_queue);	

protected:
	virtual bool DoInit(string path, int num_fields,
			    const LogField* const * fields);
	virtual bool DoWrite(int num_fields, const LogField* const * fields,
			     LogVal** vals);
	virtual bool DoSetBuf(bool enabled);
	virtual bool DoRotate(string rotated_path, string postprocessr,
			      double open, double close, bool terminating);
	virtual bool DoFlush();
	virtual void DoFinish();

private:
	typedef std::map<string, GeneralField *> ExtentMap;
	typedef ExtentMap::iterator ExtentIterator;
	bool IsSpecial(string path) 	{ return path.find("/dev/") == 0; }
	bool DoWriteOne(ODesc* desc, LogVal* val, const LogField* field);

	DataSeriesSink* log_file;
	ExtentTypeLibrary log_types;
	ExtentType *log_type;
	ExtentSeries log_series;
	OutputModule* log_output;
	ExtentMap extents; 

	// Options set from the script-level.
	uint64 ds_extent_rows; 
	uint64 ds_num_threads;
	string ds_compression;
	bool ds_dump_schema;
};

}
#endif

