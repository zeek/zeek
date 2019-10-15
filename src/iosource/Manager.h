// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <list>
#include <map>
#include <uv.h>

namespace iosource {

class IOSource;
class PktSrc;
class PktDumper;

/**
 * Singleton class managing all IOSources.
 */
class Manager {
public:

	/**
	 * Constructor.
	 */
	Manager();

	/**
	 * Destructor.
	 */
	~Manager();
									  
	/**
	 * Registers an IOSource with the manager. If the source is already
	 * registered, this method does nothing.
	 *
	 * @param src The source. The manager takes ownership.
	 * @param inactive Whether this source should be considered active
	 * or not. An active source will cause the main loop to start running,
	 * and is counted when Size() is called. This doesn't mean that an
	 * inactive source will not have data processed, but that such
	 * sources will not be the reason for the loop to continue running.
	 *
	 * @see Size
	 */
	void Register(IOSource* src, bool inactive = false);

	/**
	 * Unregisters an IOSource with the manager.
	 *
	 * @param src The source. The manager takes ownership.
	 */
	void Unregister(IOSource* src);

	/**
	 * Returns the number of packet sources plus the number of "active"
	 * sources.
	 */
	size_t Size();
	
	/**
	 * Returns a list of all registered PktSrc instances. This is a
	 * subset of all registered IOSource instances.
	 */
	PktSrc* GetPktSrc() const	{ return pkt_src; }

	/**
	 * Shut down all of the registered sources so they're removed from
	 * the uv loop. This causes the UV loop to stop on the next iteration.
	 */
	void Terminate();

	void FlushClosed();

	/**
	 * Opens a new packet source.
	 *
	 * @param path The interface or file name, as one would give to Bro \c -i.
	 *
	 * @param is_live True if \a path represents a live interface, false
	 * for a file.
	 *
	 * @return The new packet source, or null if an error occured.
	 */
	PktSrc* OpenPktSrc(const std::string& path, bool is_live);

	/**
	 * Opens a new packet dumper.
	 *
	 * @param path The file name to dump into.
	 *
	 * @param append True to append if \a path already exists.
 	 *
	 * @return The new packet dumper, or null if an error occured.
	 */
	PktDumper* OpenPktDumper(const std::string& path, bool append);

	uv_loop_t* GetLoop() const { return loop; }

	void WakeupLoop();

private:

	uv_loop_t* loop = nullptr;
	PktSrc* pkt_src = nullptr;

	using SourceMap = std::map<IOSource*, bool>;
	using PktDumperList = std::list<PktDumper*>;
	
	SourceMap sources;
	PktDumperList pkt_dumpers;

	uv_poll_t* wakeup;
};

}

extern iosource::Manager* iosource_mgr;
