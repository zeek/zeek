// See the file "COPYING" in the main distribution directory for copyright.

#ifndef LOGWRITERDS_H
#define LOGWRITERDS_H

#include <DataSeries/ExtentType.hpp>
#include <DataSeries/GeneralField.hpp>
#include <DataSeries/DataSeriesFile.hpp>
#include <DataSeries/DataSeriesModule.hpp>
#include "LogWriter.h"

class LogWriterDS : public LogWriter {
public:
	LogWriterDS();
	~LogWriterDS();

	static const size_t ROW_MIN = 2048;
	static const size_t ROW_MAX = (1024 * 1024 * 100);
	static LogWriter* Instantiate()	{ return new LogWriterDS; }

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
	string ds_compression;
	uint32 ds_extent_rows; 
	bool ds_dump_schema;
};

#endif
