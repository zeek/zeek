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

IntrusivePtr<RecordVal> EncapsulatingConn::ToVal() const
	{
	auto rv = make_intrusive<RecordVal>(BifType::Record::Tunnel::EncapsulatingConn);

	auto id_val = make_intrusive<RecordVal>(zeek::id::conn_id);
	id_val->Assign(0, make_intrusive<AddrVal>(src_addr));
	id_val->Assign(1, val_mgr->Port(ntohs(src_port), proto));
	id_val->Assign(2, make_intrusive<AddrVal>(dst_addr));
	id_val->Assign(3, val_mgr->Port(ntohs(dst_port), proto));
	rv->Assign(0, std::move(id_val));
	rv->Assign(1, BifType::Enum::Tunnel::Type->GetVal(type));

	rv->Assign(2, make_intrusive<StringVal>(uid.Base62("C").c_str()));

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
