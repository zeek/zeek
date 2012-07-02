// See the file "COPYING" in the main distribution directory for copyright.
//
// Bridge class between main process and writer threads.

#ifndef LOGGING_WRITERBACKEND_H
#define LOGGING_WRITERBACKEND_H

#include "threading/MsgThread.h"

class RemoteSerializer;

namespace logging  {

class WriterFrontend;

/**
 * Base class for writer implementation. When the logging::Manager creates a
 * new logging filter, it instantiates a WriterFrontend. That then in turn
 * creates a WriterBackend of the right type. The frontend then forwards
 * messages over the backend as its methods are called.
 *
 * All of this methods must be called only from the corresponding child
 * thread (the constructor and destructor are the exceptions.)
 */
class WriterBackend : public threading::MsgThread
{
public:
	/**
	 * Constructor.
	 *
	 * @param frontend The frontend writer that created this backend. The
	 * *only* purpose of this value is to be passed back via messages as
	 * a argument to callbacks. One must not otherwise access the
	 * frontend, it's running in a different thread.
	 *
	 * @param name A descriptive name for writer's type (e.g., \c Ascii).
	 *
	 */
	WriterBackend(WriterFrontend* frontend);

	/**
	 * Destructor.
	 */
	virtual ~WriterBackend();

	/**
	 * A struct passing information to the writer at initialization time.
	 */
	struct WriterInfo
		{
		typedef std::map<string, string> config_map;

		/**
		 * A string left to the interpretation of the writer
		 * implementation; it corresponds to the 'path' value configured
		 * on the script-level for the logging filter.
		 */
		string path;

		/**
		 * The rotation interval as configured for this writer.
		 */
		double rotation_interval;

		/**
		 * The parsed value of log_rotate_base_time in seconds.
		 */
		double rotation_base;

		/**
		 * A map of key/value pairs corresponding to the relevant
		 * filter's "config" table.
		 */
		std::map<string, string> config;

		private:
		friend class ::RemoteSerializer;

		// Note, these need to be adapted when changing the struct's
		// fields. They serialize/deserialize the struct.
		bool Read(SerializationFormat* fmt);
		bool Write(SerializationFormat* fmt) const;
		};

	/**
	 * One-time initialization of the writer to define the logged fields.
	 *
	 * @param info Meta information for the writer.
	 * @param num_fields
	 *
	 * @param fields An array of size \a num_fields with the log fields.
	 * The methods takes ownership of the array.
	 *
	 * @param frontend_name The name of the front-end writer implementation.
	 *
	 * @return False if an error occured.
	 */
	bool Init(const WriterInfo& info, int num_fields, const threading::Field* const* fields, const string& frontend_name);

	/**
	 * Writes one log entry.
	 *
	 * @param num_fields: The number of log fields for this stream. The
	 * value must match what was passed to Init().
	 *
	 * @param An array of size \a num_fields with the log values. Their
	 * types musst match with the field passed to Init(). The method
	 * takes ownership of \a vals..
	 *
	 * Returns false if an error occured, in which case the writer must
	 * not be used any further.
	 *
	 * @return False if an error occured.
	 */
	bool Write(int num_fields, int num_writes, threading::Value*** vals);

	/**
	 * Sets the buffering status for the writer, assuming the writer
	 * supports that. (If not, it will be ignored).
	 *
	 * @param enabled False if buffering is to be disabled (by default
	 * it's on).
	 *
	 * @return False if an error occured.
	 */
	bool SetBuf(bool enabled);

	/**
	 * Flushes any currently buffered output, assuming the writer
	 * supports that. (If not, it will be ignored).
	 *
	 * @return False if an error occured.
	 */
	bool Flush();

	/**
	 * Triggers rotation, if the writer supports that. (If not, it will
	 * be ignored).
	 *
	 * @return False if an error occured.
	 */
	bool Rotate(string rotated_path, double open, double close, bool terminating);

	/**
	 * Disables the frontend that has instantiated this backend. Once
	 * disabled,the frontend will not send any further message over.
	 */
	void DisableFrontend();

	/**
	 * Returns the additional writer information passed into the constructor.
	 */
	const WriterInfo& Info() const	{ return info; }

	/**
	 * Returns the number of log fields as passed into the constructor.
	 */
	int NumFields() const	{ return num_fields; }

	/**
	 * Returns the log fields as passed into the constructor.
	 */
	const threading::Field* const * Fields() const	{ return fields; }

	/**
	 * Returns the current buffering state.
	 *
	 * @return True if buffering is enabled.
	 */
	bool IsBuf()	{ return buffering; }

	/**
	 * Signals that a file has been rotated. This must be called by a
	 * writer's implementation of DoRotate() once rotation has finished.
	 *
	 * Most of the parameters should be passed through from DoRotate().
	 *
	 * @param new_name The filename of the rotated file.
	 *
	 * @param old_name The filename of the original file.
	 *
	 * @param open: The timestamp when the original file was opened.
	 *
	 * @param close: The timestamp when the origina file was closed.
	 *
	 * @param terminating: True if the original rotation request occured
	 * due to the main Bro process shutting down.
	 */
	bool FinishedRotation(string new_name, string old_name,
			      double open, double close, bool terminating);

	/** Helper method to render an IP address as a string.
	  *
	  * @param addr The address.
	  *
	  * @return An ASCII representation of the address.
	  */
	string Render(const threading::Value::addr_t& addr) const;

	/** Helper method to render an subnet value as a string.
	  *
	  * @param addr The address.
	  *
	  * @return An ASCII representation of the address.
	  */
	string Render(const threading::Value::subnet_t& subnet) const;

	/** Helper method to render a double in Bro's standard precision.
	  *
	  * @param d The double.
	  *
	  * @return An ASCII representation of the double.
	  */
	string Render(double d) const;

protected:
	friend class FinishMessage;

	/**
	 * Writer-specific intialization method.
	 *
	 * A writer implementation must override this method. If it returns
	 * false, it will be assumed that a fatal error has occured that
	 * prevents the writer from further operation; it will then be
	 * disabled and eventually deleted. When returning false, an
	 * implementation should also call Error() to indicate what happened.
	 */
	virtual bool DoInit(const WriterInfo& info, int num_fields,
			    const threading::Field* const*  fields) = 0;

	/**
	 * Writer-specific output method implementing recording of fone log
	 * entry.
	 *
	 * A writer implementation must override this method. If it returns
	 * false, it will be assumed that a fatal error has occured that
	 * prevents the writer from further operation; it will then be
	 * disabled and eventually deleted. When returning false, an
	 * implementation should also call Error() to indicate what happened.
	 */
	virtual bool DoWrite(int num_fields, const threading::Field* const*  fields,
			     threading::Value** vals) = 0;

	/**
	 * Writer-specific method implementing a change of fthe buffering
	 * state.  If buffering is disabled, the writer should attempt to
	 * write out information as quickly as possible even if doing so may
	 * have a performance impact. If enabled (which is the default), it
	 * may buffer data as helpful and write it out later in a way
	 * optimized for performance. The current buffering state can be
	 * queried via IsBuf().
	 *
	 * A writer implementation must override this method but it can just
	 * ignore calls if buffering doesn't align with its semantics.
	 *
	 * If the method returns false, it will be assumed that a fatal error
	 * has occured that prevents the writer from further operation; it
	 * will then be disabled and eventually deleted. When returning
	 * false, an implementation should also call Error() to indicate what
	 * happened.
	 */
	virtual bool DoSetBuf(bool enabled) = 0;

	/**
	 * Writer-specific method implementing flushing of its output.
	 *
	 * A writer implementation must override this method but it can just
	 * ignore calls if flushing doesn't align with its semantics.
	 *
	 * If the method returns false, it will be assumed that a fatal error
	 * has occured that prevents the writer from further operation; it
	 * will then be disabled and eventually deleted. When returning
	 * false, an implementation should also call Error() to indicate what
	 * happened.
	 */
	virtual bool DoFlush() = 0;

	/**
	 * Writer-specific method implementing log rotation.  Most directly
	 * this only applies to writers writing into files, which should then
	 * close the current file and open a new one.  However, a writer may
	 * also trigger other apppropiate actions if semantics are similar. *
	 * Once rotation has finished, the implementation must call
	 * FinishedRotation() to signal the log manager that potential
	 * postprocessors can now run.
	 *
	 * A writer implementation must override this method but it can just
	 * ignore calls if flushing doesn't align with its semantics. It
	 * still needs to call FinishedRotation() though.
	 *
	 * If the method returns false, it will be assumed that a fatal error
	 * has occured that prevents the writer from further operation; it
	 * will then be disabled and eventually deleted. When returning
	 * false, an implementation should also call Error() to indicate what
	 * happened.
	 *
	 * @param rotate_path Reflects the path to where the rotated output
	 * is to be moved, with specifics depending on the writer. It should
	 * generally be interpreted in a way consistent with that of \c path
	 * as passed into DoInit(). As an example, for file-based output, \c
	 * rotate_path could be the original filename extended with a
	 * timestamp indicating the time of the rotation.
	 *
	 * @param open The network time when the *current* file was opened.
	 *
	 * @param close The network time when the *current* file was closed.
	 *
	 * @param terminating Indicates whether the rotation request occurs
	 * due the main Bro prcoess terminating (and not because we've
	 * reached a regularly scheduled time for rotation).
	 */
	virtual bool DoRotate(string rotated_path, double open, double close,
			      bool terminating) = 0;

	/**
	 * Writer-specific method called just before the threading system is
	 * going to shutdown.
	 *
	 * This method can be overridden but one must call
	 * WriterBackend::DoFinish().
	 */
	virtual bool DoFinish() { return MsgThread::DoFinish(); }

	/**
	 * Triggered by regular heartbeat messages from the main thread.
	 *
	 * This method can be overridden but one must call
	 * WriterBackend::DoHeartbeat().
	 */
	virtual bool DoHeartbeat(double network_time, double current_time);

private:
	/**
	 * Deletes the values as passed into Write().
	 */
	void DeleteVals(int num_writes, threading::Value*** vals);

	// Frontend that instantiated us. This object must not be access from
	// this class, it's running in a different thread!
	WriterFrontend* frontend;

	WriterInfo info;	// Meta information as passed to Init().
	int num_fields;	// Number of log fields.
	const threading::Field* const*  fields;	// Log fields.
	bool buffering;	// True if buffering is enabled.
};


}

#endif

