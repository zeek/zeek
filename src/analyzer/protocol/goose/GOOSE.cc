// See the file "COPYING" in the main distribution directory for copyright.

#include "GOOSE.h"
#include "Event.h"
#include "Reporter.h"

#include "goose_pac.h"
#include "events.bif.h"

#include "gooseData.h"

#include <string>

using namespace analyzer::goose;

GOOSE_Analyzer::GOOSE_Analyzer()
	{
	goose_message = internal_handler("goose_message"); //global variable declared in events.bif.h
	}

GOOSE_Analyzer::~GOOSE_Analyzer()
	{
	}

static RecordVal * packet_info_from_packet(const Packet & pkt) {
	auto data = pkt.data;
	auto info = new RecordVal(BifType::Record::GOOSE::PacketInfo);

	// MAC Adresses :
	info->Assign(0, GOOSE_Analyzer::EthAddrToStr(data)); // Destination
	info->Assign(1, GOOSE_Analyzer::EthAddrToStr(data+6)); // Source 

	// Reception time :
	info->Assign(2, new Val(pkt.time, TYPE_DOUBLE)); 
	
	return info;
}

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
		
		auto packetInfo = packet_info_from_packet(*pkt);
		
		// generating the event
		if(msg.PDU_case_index() == binpac::GOOSE::GOOSE_PDU)
			this->GeneratePDUEvent(packetInfo, goosePdu_as_val(msg.goosePdu()));
	}

void GOOSE_Analyzer::Describe(ODesc* d) const
	{
	d->Add("<GOOSE analyzer>");
	d->NL();
	}

void GOOSE_Analyzer::GeneratePDUEvent(
		RecordVal * pInfo,
		RecordVal * gPdu)
	{
	if ( ! goose_message)
		return;

	// init the val_list
	val_list* vl = new val_list;

	// prepare the event arguments
	vl->append(pInfo);
	vl->append(gPdu);

	// Send the event
	mgr.QueueEvent(goose_message, vl);
	}

StringVal* GOOSE_Analyzer::EthAddrToStr(const u_char* addr)
	{
	char buf[18];
	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return new StringVal(buf);
	}

void GOOSE_Analyzer::Corrupted(const char* msg)
	{
	reporter->Weird(msg);
	}

