// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

namespace zeek::iosource
	{

/**
 * Interface class for components providing/consuming data inside Zeek's main
 * loop.
 */
class IOSource
	{
public:
	enum ProcessFlags
		{
		READ = 0x01,
		WRITE = 0x02
		};

	/**
	 * Constructor.
	 *
	 * @param process_fd A flag for indicating whether the child class implements
	 * the ProcessFd() method. This is used by the run loop for dispatching to the
	 * appropriate process method.
	 */
	IOSource(bool process_fd = false) : implements_process_fd(process_fd) { }

	/**
	 * Destructor.
	 */
	virtual ~IOSource() { }

	/**
	 * Returns true if more data is to be expected in the future.
	 * Otherwise, source may be removed.
	 */
	bool IsOpen() const { return ! closed; }

	/**
	 * Returns true if this is a packet source.
	 */
	virtual bool IsPacketSource() const { return false; }

	/**
	 * Initializes the source. Can be overwritten by derived classes.
	 */
	virtual void InitSource() { }

	/**
	 * Finalizes the source when it's being closed. Can be overwritten by
	 * derived classes.
	 */
	virtual void Done() { }

	/**
	 * Return the next timeout value for this source. This should be
	 * overridden by source classes where they have a timeout value
	 * that can wake up the poll.
	 *
	 * Must be overridden by derived classes.
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
	 * Optional process method that allows an IOSource to only process
	 * the file descriptor that is found ready and not every possible
	 * descriptor. If this method is implemented, true must be passed
	 * to the IOSource constructor via the child class.
	 *
	 * @param fd The file descriptor to process.
	 * @param flags Flags indicating what type of event is being
	 * processed.
	 */
	virtual void ProcessFd(int fd, int flags) { }
	bool ImplementsProcessFd() const { return implements_process_fd; }

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
	void SetClosed(bool is_closed) { closed = is_closed; }

private:
	bool closed = false;
	bool implements_process_fd = false;
	};

	} // namespace zeek::iosource
