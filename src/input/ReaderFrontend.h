// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERFRONTEND_H
#define INPUT_READERFRONTEND_H

#include "../threading/MsgThread.h"
#include "../threading/SerializationTypes.h"

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
	 * This method must only be called from the main thread.
	 */	
	void Init(string arg_source);

	/**
	 * Force an update of the current input source. Actual action depends on
	 * the opening mode and on the input source.
	 *
	 * This method generates a message to the backend reader and triggers
	 * the corresponding message there.
	 * This method must only be called from the main thread.
	 */
	void Update();

	/**
	 * Add a filter to the current input source.
	 *
	 * See ReaderBackend::AddFilter for arguments.
	 *
	 * The method takes ownership of \a fields
	 */
	void AddFilter( const int id, const int arg_num_fields, const threading::Field* const* fields );

	/**
	 * Removes a filter to the current input source.
	 */
	void RemoveFilter ( const int id );

	/**
	 * Finalizes writing to this tream.
	 *
	 * This method generates a message to the backend reader and triggers
	 * the corresponding message there.
	 * This method must only be called from the main thread.
	 */	
	void Finish();

	/**
	 * Disables the reader frontend. From now on, all method calls that
	 * would normally send message over to the backend, turn into no-ops.
	 * Note though that it does not stop the backend itself, use Finsh()
	 * to do that as well (this method is primarily for use as callback
	 * when the backend wants to disable the frontend).
	 *
	 * Disabled frontend will eventually be discarded by the
	 * input::Manager.
	 *
	 * This method must only be called from the main thread.
	 */
	void SetDisable()	{ disabled = true; }

	/**
	 * Returns true if the reader frontend has been disabled with SetDisable().
	 */
	bool Disabled()	{ return disabled; }	

	/**
	 * Returns a descriptive name for the reader, including the type of
	 * the backend and the source used.
	 *
	 * This method is safe to call from any thread.
	 */
	string Name() const;

protected:
	friend class Manager;

	/**
	 * Returns the source as passed into the constructor
	 */
	const string Source() const	{ return source; };	

	string ty_name;	// Name of the backend type. Set by the manager.

private:
	ReaderBackend* backend;	// The backend we have instanatiated.	
	string source;
	bool disabled;		// True if disabled.
	bool initialized;	// True if initialized.	

};

}


#endif /* INPUT_READERFRONTEND_H */


