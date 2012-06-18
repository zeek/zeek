@load base/frameworks/tunnels

module SOCKS;

export {
	type RequestType: enum {
		CONNECTION = 1,
		PORT       = 2,
	};
}

event socks_request(c: connection, request_type: count, dstaddr: addr, dstname: string, p: port, user: string)
	{
	Tunnel::register([$cid=c$id, $tunnel_type=Tunnel::SOCKS, $uid=c$uid]);
	}
