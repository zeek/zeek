// See the file "COPYING" in the main distribution directory for copyright.

#include "Tunnels.h"

RecordVal* EncapsulatingConn::GetRecordVal() const
	{
	RecordVal *rv =
			new RecordVal(BifType::Record::Tunnel::EncapsulatingConn);
	TransportProto tproto;
	switch ( type ) {
	case BifEnum::Tunnel::IP6_IN_IP4:
	case BifEnum::Tunnel::IP4_IN_IP4:
	case BifEnum::Tunnel::IP6_IN_IP6:
	case BifEnum::Tunnel::IP4_IN_IP6:
		tproto = TRANSPORT_UNKNOWN;
		break;
	default:
		tproto = TRANSPORT_UDP;
		break;
	} // end switch

	RecordVal* id_val = new RecordVal(conn_id);
	id_val->Assign(0, new AddrVal(src_addr));
	id_val->Assign(1, new PortVal(ntohs(src_port), tproto));
	id_val->Assign(2, new AddrVal(dst_addr));
	id_val->Assign(3, new PortVal(ntohs(dst_port), tproto));
	rv->Assign(0, id_val);
	rv->Assign(1, new EnumVal(type, BifType::Enum::Tunnel::Type));
	return rv;
	}

bool operator==(const Encapsulation& e1, const Encapsulation& e2)
	{
	if ( e1.conns )
		if ( e2.conns )
			{
			if ( e1.conns->size() != e2.conns->size() )
				return false;
			else
				for ( size_t i = 0; i < e1.conns->size(); ++i )
					if ( (*e1.conns)[i] != (*e2.conns)[i] )
						return false;
			return true;
			}
		else
			return false;
	else
		if ( e2.conns )
			return false;
		else
			return true;
	}
