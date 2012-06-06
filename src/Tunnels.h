// See the file "COPYING" in the main distribution directory for copyright.

#ifndef TUNNELS_H
#define TUNNELS_H

#include "config.h"
#include "NetVar.h"
#include "IPAddr.h"
#include "Val.h"
#include <vector>

class Connection;

class EncapsulatingConn {
public:
	EncapsulatingConn()
		: src_port(0), dst_port(0), type(BifEnum::Tunnel::NONE), uid(0)
		{}

	EncapsulatingConn(const IPAddr& s, const IPAddr& d,
	                  BifEnum::Tunnel::Type t)
		: src_addr(s), dst_addr(d), src_port(0), dst_port(0), type(t)
		{
		uid = calculate_unique_id();
		}

	EncapsulatingConn(Connection* c, BifEnum::Tunnel::Type t);

	EncapsulatingConn(const EncapsulatingConn& other)
		: src_addr(other.src_addr), dst_addr(other.dst_addr),
		  src_port(other.src_port), dst_port(other.dst_port),
		  type(other.type), uid(other.uid)
		{}

	~EncapsulatingConn()
		{}

	RecordVal* GetRecordVal() const;

	friend bool operator==(const EncapsulatingConn& ec1,
	                       const EncapsulatingConn& ec2)
		{
		if ( ec1.type != ec2.type )
			return false;
		if ( ec1.type == BifEnum::Tunnel::IP )
			return ec1.uid == ec2.uid &&
			  ((ec1.src_addr == ec2.src_addr && ec1.dst_addr == ec2.dst_addr) ||
			   (ec1.src_addr == ec2.dst_addr && ec1.dst_addr == ec2.src_addr));
		return ec1.src_addr == ec2.src_addr && ec1.dst_addr == ec2.dst_addr &&
		       ec1.src_port == ec2.src_port && ec1.dst_port == ec2.dst_port &&
		       ec1.uid == ec2.uid;
		}

	friend bool operator!=(const EncapsulatingConn& ec1,
	                       const EncapsulatingConn& ec2)
		{
		return ! ( ec1 == ec2 );
		}

	IPAddr src_addr;
	IPAddr dst_addr;
	uint16 src_port;
	uint16 dst_port;
	BifEnum::Tunnel::Type type;
	uint64 uid;
};

class Encapsulation {
public:
	Encapsulation() : conns(0)
		{}

	Encapsulation(const Encapsulation& other)
		{
		if ( other.conns )
			conns = new vector<EncapsulatingConn>(*(other.conns));
		else
			conns = 0;
		}

	Encapsulation(const Encapsulation* other)
		{
		if ( other && other->conns )
			conns = new vector<EncapsulatingConn>(*(other->conns));
		else
			conns = 0;
		}

	Encapsulation& operator=(const Encapsulation& other)
		{
		if ( this == &other ) return *this;
		delete conns;
		if ( other.conns )
			conns = new vector<EncapsulatingConn>(*(other.conns));
		else
			conns = 0;
		return *this;
		}

	~Encapsulation() { delete conns; }

	void Add(const EncapsulatingConn& c)
		{
		if ( ! conns )
			conns = new vector<EncapsulatingConn>();
		conns->push_back(c);
		}

	size_t Depth() const
		{
		return conns ? conns->size() : 0;
		}

	BifEnum::Tunnel::Type LastType() const
		{
		return conns ? (*conns)[conns->size()-1].type : BifEnum::Tunnel::NONE;
		}

	VectorVal* GetVectorVal() const
		{
		VectorVal* vv = new VectorVal(
		    internal_type("EncapsulatingConnVector")->AsVectorType());
		if ( conns )
			for ( size_t i = 0; i < conns->size(); ++i )
				vv->Assign(i, (*conns)[i].GetRecordVal(), 0);
		return vv;
		}

	friend bool operator==(const Encapsulation& e1, const Encapsulation& e2);

	friend bool operator!=(const Encapsulation& e1, const Encapsulation& e2)
		{
		return ! ( e1 == e2 );
		}

	vector<EncapsulatingConn>* conns;
};

#endif
