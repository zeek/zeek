// See the file "COPYING" in the main distribution directory for copyright.

#include "GOOSE.h"
#include "Event.h"
#include "Reporter.h"

#include "goose_pac.h"
#include "events.bif.h"

#include <string>

using namespace analyzer::goose;

GOOSE_Analyzer::GOOSE_Analyzer()
	{
	goose_message = internal_handler("goose_message"); //global variable declared in events.bif.h
	}

GOOSE_Analyzer::~GOOSE_Analyzer()
	{
	}

// Argh! FreeBSD and Linux have almost completely different net/if_goose.h .
// ... and on Solaris we are missing half of the GOOSEOP codes, so define
// them here as necessary:

void GOOSE_Analyzer::NextPacket(double t, const Packet* pkt)
	{
		binpac::GOOSE::GOOSE_Message msg;

		// parsing :
		try {
			msg.Parse(pkt->data + pkt->hdr_size, pkt->data + pkt->cap_len);
		}
		catch(binpac::Exception & e) {
			std::string errmsg("GOOSE packet parsing generated this error :\n");
			errmsg += e.c_msg();
			errmsg += "\n";

			std::cerr << "\n!!!! " <<  errmsg << std::endl;
			
			this->Corrupted(errmsg.c_str());

			return;
		}
		
		// generating the event
		if(msg.goosePdu())
			this->GeneratePDUEvent(goosePdu_as_val(msg.goosePdu()));
	}

void GOOSE_Analyzer::Describe(ODesc* d) const
	{
	d->Add("<GOOSE analyzer>");
	d->NL();
	}

void GOOSE_Analyzer::GeneratePDUEvent(RecordVal * gPdu
				/*
				double time,
				const u_char* src, const u_char *dst,
				const GOOSE_Message & message
				// */	
				)
	{
	if ( ! goose_message)
		return;

	// init the val_list
	val_list* vl = new val_list;

	// prepare the event arguments
	vl->append(gPdu);
	/*
	vl->append(EthAddrToStr(src));
	vl->append(EthAddrToStr(dst));
	vl->append(ConstructAddrVal(spa));
	vl->append(EthAddrToStr((const u_char*) sha));
	vl->append(ConstructAddrVal(tpa));
	vl->append(EthAddrToStr((const u_char*) tha));
	// */

	mgr.QueueEvent(goose_message, vl);
	}

StringVal* GOOSE_Analyzer::EthAddrToStr(const u_char* addr)
	{
	char buf[1024];
	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return new StringVal(buf);
	}

void GOOSE_Analyzer::Corrupted(const char* msg)
	{
	reporter->Weird(msg);
	}

