// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"

#include <map>
#include <string>
#include <vector>

#include "zeek/Flare.h"
#include "zeek/iosource/IOSource.h"

struct timespec;
struct kevent;

namespace zeek
	{
namespace iosource
	{

class PktSrc;
class PktDumper;

/**
 * Manager class for IO sources. This handles all of the polling of sources
 * in the main loop.
 */
class Manager
	{
public:
	struct ReadySource
		{
		IOSource* src = nullptr;
		int fd = -1;
		int flags = 0;
		};

	using ReadySources = std::vector<ReadySource>;

	/**
	 * Constructor.
	 */
	Manager();

	/**
	 * Destructor.
	 */
	virtual ~Manager();

	/**
	 * Initializes some extra fields that can't be done during the
	 * due to dependencies on other objects being initialized first.
	 */
	void InitPostScript();

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
	void Register(IOSource* src, bool dont_count = false, bool manage_lifetime = true);

	/**
	 * Returns the number of registered and still active sources,
	 * excluding those that are registered as \a dont_count.
	 */
	int Size() const { return sources.size() - dont_counts; }

	/**
	 * Returns total number of sources including dont_counts;
	 */
	int TotalSize() const { return sources.size(); }

	/**
	 * Returns the registered PktSrc. If not source is registered yet,
	 * returns a nullptr.
	 */
	PktSrc* GetPktSrc() const { return pkt_src; }

	/**
	 * Terminate all processing immediately by removing all sources (and
	 * therefore now returning a Size() of zero).
	 */
	void Terminate() { RemoveAll(); }

	/**
	 * Opens a new packet source.
	 *
	 * @param path The interface or file name, as one would give to zeek \c -i.
	 *
	 * @param is_live True if \a path represents a live interface, false
	 * for a file.
	 *
	 * @return The new packet source, or null if an error occurred.
	 */
	PktSrc* OpenPktSrc(const std::string& path, bool is_live);

	/**
	 * Opens a new packet dumper.
	 *
	 * @param path The file name to dump into.
	 *
	 * @param append True to append if \a path already exists.
	 *
	 * @return The new packet dumper, or null if an error occurred.
	 */
	PktDumper* OpenPktDumper(const std::string& path, bool append);

	/**
	 * Finds the sources that have data ready to be processed.
	 *
	 * @param ready A vector used to return the set of sources that are ready.
	 */
	void FindReadySources(ReadySources* ready);

	/**
	 * Registers a file descriptor and associated IOSource with the manager
	 * to be checked during FindReadySources. This will register the file
	 * descriptor to check for read events.
	 *
	 * @param fd A file descriptor pointing at some resource that should be
	 * checked for readiness.
	 * @param src The IOSource that owns the file descriptor.
	 * @param flags A combination of values from IOSource::ProcessFlags for
	 * which modes we should register for this file descriptor.
	 */
	bool RegisterFd(int fd, IOSource* src, int flags = IOSource::READ);

	/**
	 * Unregisters a file descriptor from the FindReadySources checks.
	 */
	bool UnregisterFd(int fd, IOSource* src, int flags = IOSource::READ);

	/**
	 * Forces the poll in FindReadySources to wake up immediately. This method
	 * is called during RegisterFd and UnregisterFd since those methods cause
	 * changes to the active set of file descriptors.
	 */
	void Wakeup(std::string_view where);

private:
	/**
	 * Calls the appropriate poll method to gather a set of IOSources that are
	 * ready for processing.
	 *
	 * @param ready a vector used to return the ready sources.
	 * @param timeout the value to be used for the timeout of the poll. This
	 * should be a value relative to the current network time, not an
	 * absolute time value. This may be zero to cause an infinite timeout or
	 * -1 to force a very short timeout.
	 * @param timeout_src The source associated with the current timeout value.
	 * This is typically a timer manager object.
	 */
	void Poll(ReadySources* ready, double timeout, IOSource* timeout_src);

	/**
	 * Converts a double timeout value into a timespec struct used for calls
	 * to kevent().
	 */
	void ConvertTimeout(double timeout, struct timespec& spec);

	/**
	 * Specialized registration method for packet sources.
	 */
	void Register(PktSrc* src);

	void RemoveAll();

	class WakeupHandler final : public IOSource
		{
	public:
		WakeupHandler();
		~WakeupHandler();

		/**
		 * Tells the handler to wake up the loop by firing the flare.
		 *
		 * @param where a string denoting where this ping was called from. Used
		 * for debugging output.
		 */
		void Ping(std::string_view where);

		// IOSource API methods
		void Process() override;
		const char* Tag() override { return "WakeupHandler"; }
		double GetNextTimeout() override { return -1; }

	private:
		zeek::detail::Flare flare;
		};

	struct Source
		{
		IOSource* src = nullptr;
		bool dont_count = false;
		bool manage_lifetime = false;
		};

	using SourceList = std::vector<Source*>;
	SourceList sources;

	using PktDumperList = std::vector<PktDumper*>;
	PktDumperList pkt_dumpers;

	PktSrc* pkt_src = nullptr;

	int dont_counts = 0;
	int zero_timeout_count = 0;
	WakeupHandler* wakeup = nullptr;
	int poll_counter = 0;
	int poll_interval = 100;

	int event_queue = -1;
	std::map<int, IOSource*> fd_map;
	std::map<int, IOSource*> write_fd_map;

	// This is only used for the output of the call to kqueue in FindReadySources().
	// The actual events are stored as part of the queue.
	std::vector<struct kevent> events;
	};

	} // namespace iosource

extern iosource::Manager* iosource_mgr;

	} // namespace zeek
