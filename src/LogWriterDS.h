// See the file "COPYING" in the main distribution directory for copyright.

#ifndef LOGWRITERDS_H
#define LOGWRITERDS_H

#include <DataSeries/ExtentType.hpp>
#include <DataSeries/GeneralField.hpp>
#include <DataSeries/DataSeriesFile.hpp>
#include <DataSeries/DataSeriesModule.hpp>
#include "LogWriter.h"

/**
 *  This class is designed to log to a given DataSeries target.  This class interacts with the main thread via event message
 *  queues (as defined in BasicThread.h and ThreadSafeQueue.h)
 */
class LogWriterDS : public LogWriter {
public:
	/**
	*  Turns script variables into a form our logger can use.
	*/
	LogWriterDS(LogEmissary& parent, QueueInterface<MessageEvent *>& in_queue, QueueInterface<MessageEvent *>& out_queue);
	/**
	 *  After a long, tiring battle in the war for network domination, our LogWriterDS will be retired.  Rest well, dude; you've earned it.
	 *
	 *  Destroys the LogWriter, and cleans up any memory allocated to it.
	 */
	~LogWriterDS();

	static const size_t ROW_MIN = 2048;                      // Minimum extent size
	static const size_t ROW_MAX = (1024 * 1024 * 100);       // Maximum extent size
	static const size_t THREAD_MIN = 1;                      // Minimum number of compression threads that DataSeries may spawn
	static const size_t THREAD_MAX = 128;                    // Maximum number of compression threads that DataSeries may spawn
	static const size_t TIME_SCALE = 1000000;                // Fixed-point multiplier for time values when converted to integers
	//TODO: I don't think this should be a configurable option in the LogWriterDS scope, but might be good for Bro in general...

	/**
 	* Builds an instance of the LogWriterDS
	* @return A fresh LogWriterDS
 	*/
	static LogWriter* Instantiate(LogEmissary& parent, QueueInterface<MessageEvent *>& in_queue, QueueInterface<MessageEvent *>& out_queue);	

// The log writer is a thread, which means interaction with this class is indirect.  Messages are passed to BasicThread, 
// which in turn calls a process() method on those messages.  The process method then calls these particular functions.
// See LogWriter.h and BasicThread.h for more information.
protected:

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
	virtual bool DoInit(string path, int num_fields,
			    const LogField* const * fields);
	/**
	 *  Writes a new record into the DataSeries object thingy.
	 *
	 *  @param num_fields Number of fields in this record
	 *  @param fields The list of fields (so we can do cool things like get field type, get field name, etc)
	 *  @param vals The values we're trying to write to the log.  Ideally, fields[i]->type == vals[i]->type
	 *  
	 *  @return true if the record was written successfully.  DataSeries will abort() otherwise, so we don't bother returning false here ...
	 */
	virtual bool DoWrite(int num_fields, const LogField* const * fields,
			     LogVal** vals);
	/**
	 *  DataSeries is *always* buffered to some degree.  This option is ignored.
	 *  @param enabled N/A
	 *  @return true always
	*/
	virtual bool DoSetBuf(bool enabled);
	
	/**
	*  Handles log rotation for DataSeries.  Note that if DS files are rotated too often, the aggregate log size will be (much) larger.
	*
	*  @param rotated_path The rotated path!
	*  @param postprocessor A script / command to run that will effectively process the generated log
	*  @param open The time at which this file was opened
	*  @param close The time at which this file was closed
	*  @param terminating Was this rotate because bro is shutting down?
	*/
	virtual bool DoRotate(string rotated_path, string postprocessr,
			      double open, double close, bool terminating);
	/**
	* Flushing is handled by DataSeries automatically, so this function doesn't do anything.
	*
	* @return true always
	*/
	virtual bool DoFlush();
	
	/**
	 *  Wrap up our files and write them out to disk.
	 *
	 *  In DataSeries' case, de-allocates relevant structures, which automatically calls flush code in their destructors.
	 *
	 *  TODO: Make Finish() work...
	 */
	virtual void DoFinish();

private:
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
	bool ds_use_integer;
	bool ds_dump_schema;
};

#endif

