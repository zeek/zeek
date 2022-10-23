// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/input/ReaderBackend.h"
#include "zeek/threading/SerialTypes.h"

namespace zeek
	{

class EnumVal;

namespace input
	{

class Manager;

/**
 * Bridge class between the input::Manager and backend input threads. The
 * Manager instantiates one \a ReaderFrontend for each open input stream.
 * Each frontend in turns instantiates a ReaderBackend-derived class
 * internally that's specific to the particular input format. That backend
 * spawns a new thread, and it receives messages from the frontend that
 * correspond to method called by the manager.
 */
class ReaderFrontend
	{
public:
	/**
	 * Constructor.
	 *
	 * info: The meta information struct for the writer.
	 *
	 * type: The backend writer type, with the value corresponding to the
	 * script-level \c Input::Reader enum (e.g., \a READER_ASCII). The
	 * frontend will internally instantiate a ReaderBackend of the
	 * corresponding type.
	 *
	 * Frontends must only be instantiated by the main thread.
	 */
	ReaderFrontend(const ReaderBackend::ReaderInfo& info, EnumVal* type);

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
	void Init(const int arg_num_fields, const threading::Field* const* fields);

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
	void Stop();

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
	void SetDisable() { disabled = true; }

	/**
	 * Returns true if the reader frontend has been disabled with
	 * SetDisable().
	 */
	bool Disabled() { return disabled; }

	/**
	 * Returns a descriptive name for the reader, including the type of
	 * the backend and the source used.
	 *
	 * This method is safe to call from any thread.
	 */
	const char* Name() const;

	/**
	 * Returns the additional reader information passed into the constructor.
	 */
	const ReaderBackend::ReaderInfo& Info() const
		{
		assert(info);
		return *info;
		}

	/**
	 * Returns the number of log fields as passed into the constructor.
	 */
	int NumFields() const { return num_fields; }

	/**
	 * Returns the log fields as passed into the constructor.
	 */
	const threading::Field* const* Fields() const { return fields; }

protected:
	friend class Manager;

private:
	ReaderBackend* backend; // The backend we have instantiated.
	ReaderBackend::ReaderInfo* info; // Meta information.
	const threading::Field* const* fields; // The input fields.
	int num_fields; // Information as passed to Init().
	bool disabled; // True if disabled.
	bool initialized; // True if initialized.
	const char* name; // Descriptive name.
	};

	} // namespace input
	} // namespace zeek
