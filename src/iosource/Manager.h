// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <list>
#include "iosource/FD_Set.h"

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
	Manager()	{ call_count = 0; dont_counts = 0; }

	/**
	 * Destructor.
	 */
	~Manager();

	/**
	 * Registers an IOSource with the manager. If the source is already
	 * registered, the method will update its *dont_count* value but not
	 * do anything else.
	 *
	 * @param src The source. The manager takes ownership.
	 *
	 * @param dont_count If true, this source does not contribute to the
	 * number of IOSources returned by Size().  The effect is that if all
	 * sources except for the non-counting ones have gone dry, processing
	 * will shut down.
	 */
	void Register(IOSource* src, bool dont_count = false);

	/**
	 * Returns the packet source with the soonest available input. This
	 * may block for a little while if all are dry.
	 *
	 * @param ts A pointer where to store the timestamp of the input that
	 * the soonest source has available next.
	 *
	 * @return The source, or null if no source has input.
	 */
	IOSource* FindSoonest(double* ts);

	/**
	 * Returns the number of registered and still active sources,
	 * excluding those that are registered as \a dont_cont.
	 */
	int Size() const	{ return sources.size() - dont_counts; }

	/**
	 * Returns the registered PktSrc. If not source is registered yet,
	 * returns a nullptr.
	 */
	PktSrc* GetPktSrc() const	{ return pkt_src; }

	/**
	 * Terminate all processing immediately by removing all sources (and
	 * therefore now returning a Size() of zero).
	 */
	void Terminate()	{ RemoveAll(); }

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

private:
	/**
	 * When looking for a source with something to process, every
	 * SELECT_FREQUENCY calls we will go ahead and block on a select().
	 */
	static const int SELECT_FREQUENCY = 25;

	/**
	 * Microseconds to wait in an empty select if no source is ready.
	 */
	static const int SELECT_TIMEOUT = 50;

	void Register(PktSrc* src);
	void RemoveAll();

	unsigned int call_count;
	int dont_counts;

	struct Source {
		IOSource* src;
		FD_Set fd_read;
		FD_Set fd_write;
		FD_Set fd_except;
		bool dont_count;

		bool Ready(fd_set* read, fd_set* write, fd_set* except) const
			{ return fd_read.Ready(read) || fd_write.Ready(write) ||
			         fd_except.Ready(except); }

		void SetFds(fd_set* read, fd_set* write, fd_set* except,
		            int* maxx) const;

		void Clear()
			{ fd_read.Clear(); fd_write.Clear(); fd_except.Clear(); }
	};

	typedef std::list<Source*> SourceList;
	SourceList sources;

	typedef std::list<PktDumper *> PktDumperList;

	PktSrc* pkt_src = nullptr;
	PktDumperList pkt_dumpers;
};

}

extern iosource::Manager* iosource_mgr;
