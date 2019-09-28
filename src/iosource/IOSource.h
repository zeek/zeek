// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <uv.h>
#include <string>
#include <map>

#include "Timer.h"

namespace iosource {

/**
 * Interface class for components providing/consuming data inside Bro's main
 * loop.
 */
class IOSource {

public:

	/**
	 * Struct for storing the source and file descriptor inside of a uv_handle_t
	 * object for later retrieval.
	 */
	struct Source {
		IOSource* source;
		int fd;
	};

	/**
	 * Constructor.
	 */
	IOSource(bool use_idle_handle = false);

	/**
	 * Destructor.
	 */
	virtual ~IOSource();

	/**
	 * Returns true if source has nothing ready to process.
	 */
	bool IsIdle() const	{ return idle; }

	/**
	 * Returns true if more data is to be expected in the future.
	 * Otherwise, source may be removed.
	 */
	bool IsOpen() const	{ return ! closed; }

	/**
	 * Initializes the source. Can be overwritten by derived classes.
	 */
	virtual void Init()	{ }

	/**
	 * Finalizes the source when it's being closed. Can be overwritten by
	 * derived classes.
	 */
	virtual void Done();

	/**
	 * Returns the tag of the timer manager associated with the last
	 * proceseed data item.
	 *
	 * Can be overridden by derived classes.
	 *
	 * @return The tag, or null for the global timer manager.
	 * 
	 */
	virtual TimerMgr::Tag* GetCurrentTag()	{ return nullptr; }

	/**
	 * Returns a descriptual tag representing the source for debugging.
	 *
	 * Can be overridden by derived classes.
	 *
	 * @return The debugging name.
	 */
	virtual const char* Tag() = 0;
	
	/**
	 * Cleans up the memory used for the uv handle. Called by the callback
	 * for uv_close() during shutdown.
	 */
	void Cleanup(int fd = -1);

	/**
	 * Handles new data coming in from libuv. This is called by the callback methods
	 * for libuv, and should be overridden in child classes to do custom data
	 * processing.
	 */
	virtual void HandleNewData(int fd) {}

	/**
	 * Returns whether this IOSource is a source of packet data. Used by the IOSource
	 * manager to register/unregister components correctly.
	 */
	virtual bool IsPacketSource() const { return false; }

protected:

	/**
	 * Adds a callback method to the loop. If a pollable file descriptor is available
	 * it can be passed as the fd argument. If one is not available, -1 can be passed
	 * and an idle handler will be created.
	 */
	bool Start(int fd = -1);

	/**
	 * Removes a callback from the loop. This method should only be called in cases
	 * where a file descriptor is added/removed from polling in normal running operations
	 * such as proxies in broker. If just shutting down, call Done() which closes all
	 * handles at once.
	 */
	void Stop(int fd = -1);

	/*
	 * Callback for derived classes to call when they have gone dry
	 * temporarily.
	 *
	 * @param is_idle True if the source is idle currently.
	 */
	void SetIdle(bool is_idle)	{ idle = is_idle; }

	/*
	 * Callback for derived class to call when they have shutdown.
	 *
	 * @param is_closed True if the source is now closed.
	 */
	void SetClosed(bool is_closed)	{ closed = is_closed; }

private:

	std::map<int, uv_poll_t*> poll_handles;
	uv_prepare_t* prepare_handle = nullptr;
	uv_idle_t* idle_handle = nullptr;

	bool use_idle_handle = false;
	bool idle = false;
	bool closed = false;
};

}
