// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"

#include <string>

namespace zeek
	{

class Packet;

namespace iosource
	{

/**
 * Base class for packet dumpers.
 */
class PktDumper
	{
public:
	/**
	 * Constructor.
	 */
	PktDumper();

	/**
	 * Destructor.
	 */
	virtual ~PktDumper();

	/**
	 * Returns the path associated with the dumper.
	 */
	const std::string& Path() const;

	/**
	 * Returns true if the dumper is open for writing.
	 */
	bool IsOpen() const;

	/**
	 * Returns the time when the dumper was opened for writing.
	 */
	double OpenTime() const;

	/**
	 * Returns returns true if the dumper has encountered an error.
	 */
	bool IsError() const;

	/**
	 * Returns if the dumper has encountered an error, returns a
	 * corresponding error message. Returns an empty string otherwise.
	 */
	const char* ErrorMsg() const;

	// PktDumper interface for derived classes to implement.

	/**
	 * Called by the manager system to open the source.
	 *
	 * Derived classes must implement this method. If successful, the
	 * implementation must call \a Opened(); if not, it must call Error()
	 * with a corresponding message.
	 */
	virtual void Open() = 0;

	/**
	 * Called by the manager system to close the dumper.
	 *
	 * Derived classes must implement this method. If successful, the
	 * implementation must call \a Closed(); if not, it must call Error()
	 * with a corresponding message.
	 */
	virtual void Close() = 0;

	/**
	 * Called to write a packet to the dumper.
	 *
	 * Derived classes must implement this method.
	 *
	 * @param pkt The packet to record.
	 *
	 * @return True if succesful, false otherwise (in which case \a
	 * Error() must have been called.)
	 */
	virtual bool Dump(const Packet* pkt) = 0;

protected:
	friend class Manager;
	friend class ManagerBase;

	/**
	 * Structure to pass back information about the packet dumper to the
	 * base class. Derived class pass an instance of this to \a Opened().
	 */
	struct Properties
		{
		std::string path;
		double open_time;
		};

	/**
	 * Called from the implementations of \a Open() to signal that the
	 * source has been successfully opened.
	 *
	 * @param props A properties instance describing the now open source.
	 */
	void Opened(const Properties& props);

	/**
	 * Called from the implementations of \a Close() to signal that the
	 * source has been closed.
	 */
	void Closed();

	/**
	 * Called from derived classes to signal an error.
	 *
	 * @param msg A corresponding error message.
	 */
	void Error(const std::string& msg);

	/**
	 * Called by the manager to initialize the dumper.
	 */
	void Init();

	/**
	 * Called by the manager to shutdown the dumper.
	 */
	void Done();

private:
	bool is_open;
	Properties props;

	std::string errmsg;
	};

	} // namespace iosource
	} // namespace zeek
