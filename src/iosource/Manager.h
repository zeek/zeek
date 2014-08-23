// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IOSOURCE_MANAGER_H
#define IOSOURCE_MANAGER_H

#include <string>
#include <list>

namespace iosource {

class IOSource;
class PktSrc;
class PktDumper;

class Manager {
public:
	Manager()	{ call_count = 0; dont_counts = 0; }
	~Manager();

	// If dont_count is true, this source does not contribute to the
	// number of IOSources returned by Size().  The effect is that
	// if all sources but the non-counting ones have gone dry,
	// processing will shut down.
	void Register(IOSource* src, bool dont_count = false);

	// This may block for some time.
	IOSource* FindSoonest(double* ts);

	int Size() const	{ return sources.size() - dont_counts; }

	typedef std::list<PktSrc *> PktSrcList;
	const PktSrcList& GetPktSrcs() const	{ return pkt_srcs; }

	// Terminate IOSource processing immediately by removing all
	// sources (and therefore returning a Size() of zero).
	void Terminate()	{ RemoveAll(); }

	PktSrc* OpenPktSrc(const std::string& path, const std::string& filter, bool is_live);
	PktDumper* OpenPktDumper(const std::string& path, bool append);

protected:
	void Register(PktSrc* src);

	// When looking for a source with something to process,
	// every SELECT_FREQUENCY calls we will go ahead and
	// block on a select().
	static const int SELECT_FREQUENCY = 25;

	// Microseconds to wait in an empty select if no source is ready.
	static const int SELECT_TIMEOUT = 50;

	void RemoveAll();

	unsigned int call_count;
	int dont_counts;

	struct Source {
		IOSource* src;
		int fd_read;
		int fd_write;
		int fd_except;
	};

	typedef std::list<Source*> SourceList;
	SourceList sources;

	typedef std::list<PktDumper *> PktDumperList;

	PktSrcList pkt_srcs;
	PktDumperList pkt_dumpers;
};

}

extern iosource::Manager* iosource_mgr;

#endif

