// See the file "COPYING" in the main distribution directory for copyright.

#include "TunnelEncapsulation.h"
#include "util.h"
#include "Conn.h"

EncapsulatingConn::EncapsulatingConn(Connection* c, BifEnum::Tunnel::Type t)
		: src_addr(c->OrigAddr()), dst_addr(c->RespAddr()),
		  src_port(c->OrigPort()), dst_port(c->RespPort()),
		  proto(c->ConnTransport()), type(t), uid(c->GetUID())
	{
	if ( ! uid )
		{
		uid.Set(bits_per_uid);
		c->SetUID(uid);
		}
	}

RecordVal* EncapsulatingConn::GetRecordVal() const
	{
	RecordVal *rv = new RecordVal(BifType::Record::Tunnel::EncapsulatingConn);

	RecordVal* id_val = new RecordVal(conn_id);
	id_val->Assign(0, new AddrVal(src_addr));
	id_val->Assign(1, new PortVal(ntohs(src_port), proto));
	id_val->Assign(2, new AddrVal(dst_addr));
	id_val->Assign(3, new PortVal(ntohs(dst_port), proto));
	rv->Assign(0, id_val);
	rv->Assign(1, new EnumVal(type, BifType::Enum::Tunnel::Type));

	rv->Assign(2, new StringVal(uid.Base62("C").c_str()));

	return rv;
	}

bool operator==(const EncapsulationStack& e1, const EncapsulationStack& e2)
	{
	if ( ! e1.conns )
		return e2.conns;

	if ( ! e2.conns )
		return false;

	if ( e1.conns->size() != e2.conns->size() )
		return false;

	for ( size_t i = 0; i < e1.conns->size(); ++i )
		{
		if ( (*e1.conns)[i] != (*e2.conns)[i] )
			return false;
		}

	return true;
	}
