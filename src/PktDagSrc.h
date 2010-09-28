// $Id: PktDagSrc.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.
//
// Support for Endace's DAG interface card.
//
// Caveats:
//    - No support for hardware-side filtering yet.
//    - No support for secondary filter path yet.
//    - No support for other media than Ethernet.
//    - Mutex should be per interface
//    - No support for multiple rx streams

#ifndef PKTDAGSRC_H
#define PKTDAGSRC_H

#ifdef USE_DAG

extern int snaplen;

#include "PktSrc.h"

class PktDagSrc : public PktSrc {
public:
	PktDagSrc(const char* interface, const char* filter,
			PktSrc_Filter_Type ft = TYPE_FILTER_NORMAL);
	virtual ~PktDagSrc();

	// PktSrc interface:
	virtual void Statistics(Stats* stats);
	virtual int SetFilter(int index);
	virtual int SetNewFilter(const char* filter);

protected:
	virtual int ExtractNextPacket();
	virtual void GetFds(int* read, int* write, int* except);
	virtual void Close();

	void Error(const char* str);

	static const unsigned int EXTRA_WINDOW_SIZE = 4 * 1024 * 1024;
	static const int stream_num = 0;	// use receive stream 0

	// Unfortunaly the DAG API has some problems with locking streams,
	// so we do our own checks to ensure we don't use more than one
	// stream.   In particular, the secondary filter won't work.
	static int mutex;

	int fd;
	bpf_program* current_filter;
};
#endif

#endif
