# $Id: tftp.bro 4758 2007-08-10 06:49:23Z vern $

# Very simplistic - doesn't pick up the replies.

@load notice
@load udp-common
@load site

module TFTP;

export {
	redef enum Notice += {
		OutboundTFTP,		# outbound TFTP seen
	};
}

redef capture_filters += { ["tftp"] = "udp port 69" };

global tftp_notice_count: table[addr] of count &default = 0 &read_expire = 7 days;

event udp_request(u: connection)
	{
	if ( u$id$resp_p == 69/udp && u$id$orig_p >= 1024/udp )
		{
		local src = u$id$orig_h;
		local dst = u$id$resp_h;

		if ( is_local_addr(src) && ! is_local_addr(dst) &&
		     ++tftp_notice_count[src] == 1 )
			NOTICE([$note=OutboundTFTP, $conn=u,
				$msg=fmt("outbound TFTP: %s -> %s", src, dst)]);
		}
	}
