// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERBACKEND_H
#define INPUT_READERBACKEND_H

#include "BroString.h"

#include "threading/SerialTypes.h"
#include "threading/MsgThread.h"

namespace input {

/**
 * The modes a reader can be in.
 */
enum ReaderMode {
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
	MODE_STREAM
};

class ReaderFrontend;

/**
 * Base class for reader implementation. When the input:Manager creates a new
 * input stream, it instantiates a ReaderFrontend. That then in turn creates
 * a ReaderBackend of the right type. The frontend then forwards messages
 * over the backend as its methods are called.
 *
 * All methods must be called only from the corresponding child thread (the
 * constructor is the one exception.)
 */
class ReaderBackend : public threading::MsgThread {
public:
	/**
	 * Constructor.
	 *
	 * @param frontend The frontend reader that created this backend. The
	 * *only* purpose of this value is to be passed back via messages as
	 * an argument to callbacks. One must not otherwise access the
	 * frontend, it's running in a different thread.
	 */
	ReaderBackend(ReaderFrontend* frontend);

	/**
	 * Destructor.
	 */
	virtual ~ReaderBackend();

	/**
	 * A struct passing information to the reader at initialization time.
	 */
	struct ReaderInfo
		{
		typedef std::map<string, string> config_map;

		/**
		 * A string left to the interpretation of the reader 
		 * implementation; it corresponds to the value configured on
		 * the script-level for the logging filter.
		 */
		string source;

		/**
		 * A map of key/value pairs corresponding to the relevant
		 * filter's "config" table.
		 */
		config_map config;

		/**
		 * The opening mode for the input source.
		 */
		ReaderMode mode;
/*
 * I don't think the input framework needs remote serialization. If it doesn't, kill this. If it does add ReaderMode.
		private:
		friend class ::RemoteSerializer;

		// Note, these need to be adapted when changing the struct's
		// fields. They serialize/deserialize the struct.
		bool Read(SerializationFormat* fmt);
		bool Write(SerializationFormat* fmt) const;

		*/
		};
	
	/**
	 * One-time initialization of the reader to define the input source.
	 *
	 * @param @param info Meta information for the writer. 
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
	bool Init(const ReaderInfo& info, int num_fields, const threading::Field* const* fields);

	/**
	 * Finishes reading from this input stream in a regular fashion. Must
	 * not be called if an error has been indicated earlier. After
	 * calling this, no further reading from the stream can be performed.
	 *
	 * @return False if an error occured.
	 */
	void Close();

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
	const threading::Field* const * Fields() const	{ return fields; }

	/**
	 * Returns the additional reader information into the constructor.
	 */
	const ReaderInfo& Info() const	{ return info; }

	/**
	 * Returns the number of log fields as passed into the constructor.
	 */
	int NumFields() const	{ return num_fields; }
	

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
	 * in here only for convinience.
	 */
	virtual bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* fields) = 0;

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
	 * Method allowing a reader to send a specified Bro event. Vals must
	 * match the values expected by the bro event.
	 *
	 * @param name name of the bro event to send
	 *
	 * @param num_vals number of entries in \a vals
	 *
	 * @param vals the values to be given to the event
	 */
	void SendEvent(const string& name, const int num_vals, threading::Value* *vals);

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
	 * Method allowing a reader to delete a specific value from a Bro
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
	 * Method allowing a reader to clear a Bro table.
	 *
	 * If the receiving stream is an event stream, this is ignored.
	 *
	 */
	void Clear();

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

	/**
	 * Triggered by regular heartbeat messages from the main thread.
	 *
	 * This method can be overridden but once must call
	 * ReaderBackend::DoHeartbeat().
	 */
	virtual bool DoHeartbeat(double network_time, double current_time);

	/**
	 *  Convert a string into a TransportProto. This is just a utility
	 *  function for Readers.
	 *
	 * @param proto the transport protocol
	 */
	TransportProto StringToProto(const string &proto);

	/**
	 * Convert a string into a Value::addr_t.  This is just a utility
	 * function for Readers.
	 *
	 * @param addr containing an ipv4 or ipv6 address
	 */
	threading::Value::addr_t StringToAddr(const string &addr);

private:
	// Frontend that instantiated us. This object must not be accessed
	// from this class, it's running in a different thread!
	ReaderFrontend* frontend;

	ReaderInfo info;
	unsigned int num_fields;
	const threading::Field* const * fields; // raw mapping

	bool disabled;
};

}

#endif /* INPUT_READERBACKEND_H */
