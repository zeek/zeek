// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERFRONTEND_H
#define INPUT_READERFRONTEND_H

#include "ReaderBackend.h"

#include "threading/MsgThread.h"
#include "threading/SerialTypes.h"

namespace input {

class Manager;

/**
 * Bridge class between the input::Manager and backend input threads. The
 * Manager instantiates one \a ReaderFrontend for each open input stream.
 * Each frontend in turns instantiates a ReaderBackend-derived class
 * internally that's specific to the particular input format. That backend
 * spawns a new thread, and it receives messages from the frontend that
 * correspond to method called by the manager.
 */
class ReaderFrontend {
public:
	/**
	 * Constructor.
	 *
	 * type: The backend writer type, with the value corresponding to the
	 * script-level \c Input::Reader enum (e.g., \a READER_ASCII). The
	 * frontend will internally instantiate a ReaderBackend of the
	 * corresponding type.
	 *
	 * Frontends must only be instantiated by the main thread.
	 */
	ReaderFrontend(bro_int_t type);

	/**
	 * Destructor.
	 *
	 * Frontends must only be destroyed by the main thread.
	 */
	virtual ~ReaderFrontend();

	/**
	 * Initializes the reader.
	 *
	 * This method generates a message to the backend reader and triggers
	 * the corresponding message there. If the backend method fails, it
	 * sends a message back that will asynchronously call Disable().
	 *
	 * See ReaderBackend::Init() for arguments.
	 *
	 * This method must only be called from the main thread.
	 */
	void Init(const ReaderBackend::ReaderInfo& info, ReaderMode mode, const int arg_num_fields, const threading::Field* const* fields);

	/**
	 * Force an update of the current input source. Actual action depends
	 * on the opening mode and on the input source.
	 *
	 * This method generates a message to the backend reader and triggers
	 * the corresponding message there.
	 *
	 * This method must only be called from the main thread.
	 */
	void Update();

	/**
	 * Finalizes reading from this stream.
	 *
	 * This method generates a message to the backend reader and triggers
	 * the corresponding message there. This method must only be called
	 * from the main thread.
	 */
	void Close();

	/**
	 * Disables the reader frontend. From now on, all method calls that
	 * would normally send message over to the backend, turn into no-ops.
	 * Note though that it does not stop the backend itself, use Finish()
	 * to do that as well (this method is primarily for use as callback
	 * when the backend wants to disable the frontend).
	 *
	 * Disabled frontends will eventually be discarded by the
	 * input::Manager.
	 *
	 * This method must only be called from the main thread.
	 */
	void SetDisable()	{ disabled = true; }

	/**
	 * Returns true if the reader frontend has been disabled with
	 * SetDisable().
	 */
	bool Disabled()	{ return disabled; }

	/**
	 * Returns a descriptive name for the reader, including the type of
	 * the backend and the source used.
	 *
	 * This method is safe to call from any thread.
	 */
	string Name() const;

	/**
	 * Returns the additional reader information into the constructor.
	 */
	const ReaderBackend::ReaderInfo& Info() const	{ return info; }

	/**
	 * Returns the number of log fields as passed into the constructor.
	 */
	int NumFields() const	{ return num_fields; }	

	/**
	 * Returns the log fields as passed into the constructor.
	 */
	const threading::Field* const * Fields() const	{ return fields; }	

protected:
	friend class Manager;

	/**
	 * Returns the name of the backend's type.
	 */
	const string& TypeName() const	{ return ty_name; }

private:
	ReaderBackend* backend;	// The backend we have instanatiated.
	ReaderBackend::ReaderInfo info;	// Meta information as passed to Init().
	const threading::Field* const*  fields;	// The log fields.	
	int num_fields;		// Information as passed to init();
	string ty_name;		// Backend type, set by manager.
	bool disabled;		// True if disabled.
	bool initialized;	// True if initialized.
};

}


#endif /* INPUT_READERFRONTEND_H */


