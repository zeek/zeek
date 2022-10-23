// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/ZeekString.h"
#include "zeek/input/Component.h"
#include "zeek/threading/MsgThread.h"
#include "zeek/threading/SerialTypes.h"

namespace zeek::detail
	{
class Location;
	}

namespace zeek::input
	{

class ReaderFrontend;

/**
 * The modes a reader can be in.
 */
enum ReaderMode
	{
	/**
	 * Manual refresh reader mode. The reader will read the file once,
	 * and send all read data back to the manager. After that, no automatic
	 * refresh should happen. Manual refreshes can be triggered from the
	 * scripting layer using force_update.
	 */
	MODE_MANUAL,

	/**
	 * Automatic rereading mode. The reader should monitor the
	 * data source for changes continually. When the data source changes,
	 * either the whole file has to be resent using the SendEntry/EndCurrentSend functions.
	 */
	MODE_REREAD,

	/**
	 * Streaming reading mode. The reader should monitor the data source
	 * for new appended data. When new data is appended is has to be sent
	 * using the Put api functions.
	 */
	MODE_STREAM,

	/** Internal dummy mode for initialization. */
	MODE_NONE
	};

/**
 * Base class for reader implementation. When the input:Manager creates a new
 * input stream, it instantiates a ReaderFrontend. That then in turn creates
 * a ReaderBackend of the right type. The frontend then forwards messages
 * over the backend as its methods are called.
 *
 * All methods must be called only from the corresponding child thread (the
 * constructor is the one exception.)
 */
class ReaderBackend : public threading::MsgThread
	{
public:
	// Silence a warning from clang about hidden overloaded functions and the
	// Info() function that this class provides.
	using threading::MsgThread::Error;
	using threading::MsgThread::Info;
	using threading::MsgThread::Warning;

	/**
	 * Constructor.
	 *
	 * @param frontend The frontend reader that created this backend. The
	 * *only* purpose of this value is to be passed back via messages as
	 * an argument to callbacks. One must not otherwise access the
	 * frontend, it's running in a different thread.
	 */
	explicit ReaderBackend(ReaderFrontend* frontend);

	/**
	 * Destructor.
	 */
	~ReaderBackend() override;

	/**
	 * A struct passing information to the reader at initialization time.
	 */
	struct ReaderInfo
		{
		// Structure takes ownership of the strings.
		using config_map = std::map<const char*, const char*, util::CompareString>;

		/**
		 * A string left to the interpretation of the reader
		 * implementation; it corresponds to the value configured on
		 * the script-level for the logging filter.
		 *
		 * Structure takes ownership of the string.
		 */
		const char* source;

		/**
		 * The name of the input stream.
		 */
		const char* name;

		/**
		 * A map of key/value pairs corresponding to the relevant
		 * filter's "config" table.
		 */
		config_map config;

		/**
		 * The opening mode for the input source.
		 */
		ReaderMode mode;

		ReaderInfo()
			{
			source = nullptr;
			name = nullptr;
			mode = MODE_NONE;
			}

		ReaderInfo(const ReaderInfo& other)
			{
			source = other.source ? util::copy_string(other.source) : nullptr;
			name = other.name ? util::copy_string(other.name) : nullptr;
			mode = other.mode;

			for ( config_map::const_iterator i = other.config.begin(); i != other.config.end();
			      i++ )
				config.insert(
					std::make_pair(util::copy_string(i->first), util::copy_string(i->second)));
			}

		~ReaderInfo()
			{
			delete[] source;
			delete[] name;

			for ( config_map::iterator i = config.begin(); i != config.end(); i++ )
				{
				delete[] i->first;
				delete[] i->second;
				}
			}

	private:
		const ReaderInfo& operator=(const ReaderInfo& other); // Disable.
		};

	/**
	 * One-time initialization of the reader to define the input source.
	 *
	 * @param info Meta information for the writer.
	 *
	 * @param num_fields Number of fields contained in \a fields.
	 *
	 * @param fields The types and names of the fields to be retrieved
	 * from the input source.
	 *
	 * @param config A string map containing additional configuration options
	 * for the reader.
	 *
	 * @return False if an error occured.
	 */
	bool Init(int num_fields, const threading::Field* const* fields);

	/**
	 * Force trigger an update of the input stream. The action that will
	 * be taken depends on the current read mode and the individual input
	 * backend.
	 *
	 * An backend can choose to ignore this.
	 *
	 * @return False if an error occured.
	 */
	bool Update();

	/**
	 * Disables the frontend that has instantiated this backend. Once
	 * disabled, the frontend will not send any further message over.
	 */
	void DisableFrontend();

	/**
	 * Returns the log fields as passed into the constructor.
	 */
	const threading::Field* const* Fields() const { return fields; }

	/**
	 * Returns the additional reader information into the constructor.
	 */
	const ReaderInfo& Info() const { return *info; }

	/**
	 * Returns the number of log fields as passed into the constructor.
	 */
	int NumFields() const { return num_fields; }

	/**
	 * Convenience function that calls Warning or Error, depending on the
	 * is_error parameter. In case of a warning, setting suppress_future to
	 * true will suppress all future warnings until StopWarningSuppression()
	 * is called.
	 *
	 * @param is_error If set to true, an error is generated. Else a warning
	 *                 is generate.
	 *
	 * @param msg The error/warning message.
	 *
	 * @param suppress_future If set to true, future warnings are suppressed
	 *                        until StopWarningSuppression is called.
	 */
	void FailWarn(bool is_error, const char* msg, bool suppress_future = false);

	inline void StopWarningSuppression() { suppress_warnings = false; };

	// Overridden from MsgThread.
	bool OnHeartbeat(double network_time, double current_time) override;
	bool OnFinish(double network_time) override;

	void Info(const char* msg) override;

	/**
	 * Reports a warning in the child thread. For input readers, warning suppression
	 * that is caused by calling FailWarn() is respected by the Warning function.
	 */
	void Warning(const char* msg) override;

	/**
	 * Reports an error in the child thread. For input readers, it is assumed
	 * that Info and Warnings do not cause the read operation to fail (they might
	 * signal that, e.g., a single line was ignored).
	 *
	 * It is assumed that Errors are not recoverable. Calling the Error function
	 * will return the error back to scriptland and also *automatically* causes
	 * the current reader to be disabled and torn down.
	 */
	void Error(const char* msg) override;

protected:
	// Methods that have to be overwritten by the individual readers

	/**
	 * Reader-specific intialization method. Note that data may only be
	 * read from the input source after the Init() function has been
	 * called.
	 *
	 * A reader implementation must override this method. If it returns
	 * false, it will be assumed that a fatal error has occured that
	 * prevents the reader from further operation; it will then be
	 * disabled and eventually deleted. When returning false, an
	 * implementation should also call Error() to indicate what happened.
	 *
	 * Arguments are the same as Init().
	 *
	 * Note that derived classes don't need to store the values passed in
	 * here if other methods need them to; the \a ReaderBackend class
	 * provides accessor methods to get them later, and they are passed
	 * in here only for convenience.
	 */
	virtual bool DoInit(const ReaderInfo& info, int arg_num_fields,
	                    const threading::Field* const* fields) = 0;

	/**
	 * Reader-specific method implementing input finalization at
	 * termination.
	 *
	 * A reader implementation must override this method but it can just
	 * ignore calls if an input source can't actually be closed.
	 *
	 * After the method is called, the writer will be deleted. If an
	 * error occurs during shutdown, an implementation should also call
	 * Error() to indicate what happened.
	 */
	virtual void DoClose() = 0;

	/**
	 * Reader-specific method implementing the forced update trigger.
	 *
	 * A reader implementation must override this method but it can just
	 * ignore calls if a forced update does not fit the input source or
	 * the current input reading mode.
	 *
	 * If it returns false, it will be assumed that a fatal error has
	 * occured that prevents the reader from further operation; it will
	 * then be disabled and eventually deleted. When returning false, an
	 * implementation should also call Error to indicate what happened.
	 */
	virtual bool DoUpdate() = 0;

	/**
	 * Triggered by regular heartbeat messages from the main thread.
	 */
	virtual bool DoHeartbeat(double network_time, double current_time) = 0;

	// Content-sending-functions (simple mode). Include table-specific
	// functionality that simply is not used if we have no table.

	/**
	 * Method allowing a reader to send a list of values read from a
	 * specific stream back to the manager in simple mode.
	 *
	 * If the stream is a table stream, the values are inserted into the
	 * table; if it is an event stream, the event is raised.
	 *
	 * @param val Array of threading::Values expected by the stream. The
	 * array must have exactly NumEntries() elements.
	 */
	void Put(threading::Value** val);

	/**
	 * Method allowing a reader to delete a specific value from a Zeek
	 * table.
	 *
	 * If the receiving stream is an event stream, only a removed event
	 * is raised.
	 *
	 * @param val Array of threading::Values expected by the stream. The
	 * array must have exactly NumEntries() elements.
	 */
	void Delete(threading::Value** val);

	/**
	 * Method allowing a reader to clear a Zeek table.
	 *
	 * If the receiving stream is an event stream, this is ignored.
	 *
	 */
	void Clear();

	/**
	 * Method telling the manager that we finished reading the current
	 * data source. Will trigger an end_of_data event.
	 *
	 * Note: When using SendEntry as the tracking mode this is triggered
	 * automatically by EndCurrentSend(). Only use if not using the
	 * tracking mode. Otherwise the event will be sent twice.
	 */
	void EndOfData();

	// Content-sending-functions (tracking mode): Only changed lines are propagated.

	/**
	 * Method allowing a reader to send a list of values read from
	 * specific stream back to the manager in tracking mode.
	 *
	 * If the stream is a table stream, the values are inserted into the
	 * table; if it is an event stream, the event is raised.
	 *
	 * @param val Array of threading::Values expected by the stream. The
	 * array must have exactly NumEntries() elements.
	 */
	void SendEntry(threading::Value** vals);

	/**
	 * Method telling the manager, that the current list of entries sent
	 * by SendEntry is finished.
	 *
	 * For table streams, all entries that were not updated since the
	 * last EndCurrentSend will be deleted, because they are no longer
	 * present in the input source
	 */
	void EndCurrentSend();

private:
	// Frontend that instantiated us. This object must not be accessed
	// from this class, it's running in a different thread!
	ReaderFrontend* frontend;

	ReaderInfo* info;
	unsigned int num_fields;
	const threading::Field* const* fields; // raw mapping

	bool disabled;
	// this is an internal indicator in case the read is currently in a failed state
	// it's used to suppress duplicate error messages.
	bool suppress_warnings = false;
	};

	} // namespace zeek::input
