// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

namespace zeek::iosource {

/**
 * Interface class for components providing/consuming data inside Bro's main
 * loop.
 */
class IOSource {
public:
	/**
	 * Constructor.
	 */
	IOSource()	{ closed = false; }

	/**
	 * Destructor.
	 */
	virtual ~IOSource()	{}

	/**
	 * Returns true if more data is to be expected in the future.
	 * Otherwise, source may be removed.
	 */
	bool IsOpen() const	{ return ! closed; }

	/**
	 * Returns true if this is a packet source.
	 */
	virtual bool IsPacketSource() const { return false; }

	/**
	 * Initializes the source. Can be overwritten by derived classes.
	 */
	virtual void InitSource()	{ }

	/**
	 * Finalizes the source when it's being closed. Can be overwritten by
	 * derived classes.
	 */
	virtual void Done()	{ }

	/**
	 * Return the next timeout value for this source. This should be
	 * overridden by source classes where they have a timeout value
	 * that can wake up the poll.
	 *
	 * Must be overriden by derived classes.
	 *
	 * @return A value for the next time that the source thinks the
	 * poll should time out in seconds from the current time. Return
	 * -1 if this source should not be considered. This should be a
	 * a value relative to network_time, not an absolute time.
	 */
	virtual double GetNextTimeout() = 0;

	/**
	 * Processes and consumes next data item. This will be called by
	 * net_run when this IOSource has been marked ready.
	 *
	 * Must be overridden by derived classes.
	 */
	virtual void Process() = 0;

	/**
	 * Returns a descriptive tag representing the source for debugging.
	 *
	 * Must be overridden by derived classes.
	 *
	 * @return The debugging name.
	 */
	virtual const char* Tag() = 0;

protected:

	/*
	 * Callback for derived class to call when they have shutdown.
	 *
	 * @param is_closed True if the source is now closed.
	 */
	void SetClosed(bool is_closed)	{ closed = is_closed; }

private:
	bool closed;
};

} // namespace zeek::iosource
