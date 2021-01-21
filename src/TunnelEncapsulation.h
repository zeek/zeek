// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

#include <vector>

#include "zeek/NetVar.h"
#include "zeek/IPAddr.h"
#include "zeek/ID.h"
#include "zeek/UID.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Connection, zeek);

namespace zeek {

/**
 * Represents various types of tunnel "connections", that is, a pair of
 * endpoints whose communication encapsulates inner IP packets.  This could
 * mean IP packets nested inside IP packets or IP packets nested inside a
 * transport layer protocol.  EncapsulatingConn's are assigned a UID, which can
 * be shared with Connection's in the case the tunnel uses a transport-layer.
 */
class EncapsulatingConn {
public:
	/**
	 * Default tunnel connection constructor.
	 */
	EncapsulatingConn()
		: src_port(0), dst_port(0), proto(TRANSPORT_UNKNOWN),
		  type(BifEnum::Tunnel::NONE), uid()
		{}

	/**
	 * Construct an IP tunnel "connection" with its own UID.
	 * The assignment of "source" and "destination" addresses here can be
	 * arbitrary, comparison between EncapsulatingConn objects will treat IP
	 * tunnels as equivalent as long as the same two endpoints are involved.
	 *
	 * @param s The tunnel source address, likely taken from an IP header.
	 * @param d The tunnel destination address, likely taken from an IP header.
	 * @param t The type of IP tunnel.
	 */
	EncapsulatingConn(const IPAddr& s, const IPAddr& d,
	                  BifEnum::Tunnel::Type t = BifEnum::Tunnel::IP)
		: src_addr(s), dst_addr(d), src_port(0), dst_port(0),
		  proto(TRANSPORT_UNKNOWN), type(t),
		  uid(UID(detail::bits_per_uid))
		{
		}

	/**
	 * Construct a tunnel connection using information from an already existing
	 * transport-layer-aware connection object.
	 *
	 * @param c The connection from which endpoint information can be extracted.
	 *        If it already has a UID associated with it, that gets inherited,
	 *        otherwise a new UID is created for this tunnel and \a c.
	 * @param t The type of tunneling that is occurring over the connection.
	 */
	EncapsulatingConn(Connection* c, BifEnum::Tunnel::Type t);

	/**
	 * Copy constructor.
	 */
	EncapsulatingConn(const EncapsulatingConn& other)
		: src_addr(other.src_addr), dst_addr(other.dst_addr),
		  src_port(other.src_port), dst_port(other.dst_port),
		  proto(other.proto), type(other.type), uid(other.uid)
		{}

	/**
	 * Destructor.
	 */
	~EncapsulatingConn()
		{}

	BifEnum::Tunnel::Type Type() const
		{ return type; }

	/**
	 * Returns record value of type "EncapsulatingConn" representing the tunnel.
	 */
	RecordValPtr ToVal() const;

	friend bool operator==(const EncapsulatingConn& ec1,
	                       const EncapsulatingConn& ec2)
		{
		if ( ec1.type != ec2.type )
			return false;

		if ( ec1.type == BifEnum::Tunnel::IP ||
		     ec1.type == BifEnum::Tunnel::GRE )
			// Reversing endpoints is still same tunnel.
			return ec1.uid == ec2.uid && ec1.proto == ec2.proto &&
			  ((ec1.src_addr == ec2.src_addr && ec1.dst_addr == ec2.dst_addr) ||
			   (ec1.src_addr == ec2.dst_addr && ec1.dst_addr == ec2.src_addr));

		if ( ec1.type == BifEnum::Tunnel::VXLAN )
			// Reversing endpoints is still same tunnel, destination port is
			// always the same.
			return ec1.dst_port == ec2.dst_port &&
			       ec1.uid == ec2.uid && ec1.proto == ec2.proto &&
			  ((ec1.src_addr == ec2.src_addr && ec1.dst_addr == ec2.dst_addr) ||
			   (ec1.src_addr == ec2.dst_addr && ec1.dst_addr == ec2.src_addr));

		return ec1.src_addr == ec2.src_addr && ec1.dst_addr == ec2.dst_addr &&
		       ec1.src_port == ec2.src_port && ec1.dst_port == ec2.dst_port &&
		       ec1.uid == ec2.uid && ec1.proto == ec2.proto;
		}

	friend bool operator!=(const EncapsulatingConn& ec1,
	                       const EncapsulatingConn& ec2)
		{
		return ! ( ec1 == ec2 );
		}

protected:
	IPAddr src_addr;
	IPAddr dst_addr;
	uint16_t src_port;
	uint16_t dst_port;
	TransportProto proto;
	BifEnum::Tunnel::Type type;
	UID uid;
};

/**
 * Abstracts an arbitrary amount of nested tunneling.
 */
class EncapsulationStack {
public:
	EncapsulationStack() : conns(nullptr)
		{}

	EncapsulationStack(const EncapsulationStack& other)
		{
		if ( other.conns )
			conns = new std::vector<EncapsulatingConn>(*(other.conns));
		else
			conns = nullptr;
		}

	EncapsulationStack& operator=(const EncapsulationStack& other)
		{
		if ( this == &other )
			return *this;

		delete conns;

		if ( other.conns )
			conns = new std::vector<EncapsulatingConn>(*(other.conns));
		else
			conns = nullptr;

		return *this;
		}

	~EncapsulationStack() { delete conns; }

	/**
	 * Add a new inner-most tunnel to the EncapsulationStack.
	 *
	 * @param c The new inner-most tunnel to append to the tunnel chain.
	 */
	void Add(const EncapsulatingConn& c)
		{
		if ( ! conns )
			conns = new std::vector<EncapsulatingConn>();

		conns->push_back(c);
		}

	/**
	 * Return how many nested tunnels are involved in a encapsulation, zero
	 * meaning no tunnels are present.
	 */
	size_t Depth() const
		{
		return conns ? conns->size() : 0;
		}

	/**
	 * Return the tunnel type of the inner-most tunnel.
	 */
	BifEnum::Tunnel::Type LastType() const
		{
		return conns ? (*conns)[conns->size()-1].Type() : BifEnum::Tunnel::NONE;
		}

	/**
	 * Get the value of type "EncapsulatingConnVector" represented by the
	 * entire encapsulation chain.
	 */
	VectorValPtr ToVal() const
		{
		auto vv = make_intrusive<VectorVal>(
		    id::find_type<VectorType>("EncapsulatingConnVector"));

		if ( conns )
			{
			for ( size_t i = 0; i < conns->size(); ++i )
				vv->Assign(i, (*conns)[i].ToVal());
			}

		return vv;
		}

	friend bool operator==(const EncapsulationStack& e1,
	                       const EncapsulationStack& e2);

	friend bool operator!=(const EncapsulationStack& e1,
	                       const EncapsulationStack& e2)
		{
		return ! ( e1 == e2 );
		}

protected:
	std::vector<EncapsulatingConn>* conns;
};

} // namespace zeek
