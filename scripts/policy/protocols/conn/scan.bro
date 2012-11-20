##! Scan detection
##!
##! ..Authors: Sheharbano Kattack
##!            Seth Hall
##!            All the authors of the old scan.bro

@load base/frameworks/notice
@load base/frameworks/metrics

module Scan;

export {
	redef enum Notice::Type += {
		AddressScan,
		PortScan,
		};

	const analyze_addr_scan = T &redef;
	const analyze_port_scan = T &redef;

	## Interval at which to watch for the
	## :bro:id:`Scan::conn_failed_(port|addr)_threshold` variable to be crossed.
	## At the end of each interval the counter is reset.
	const conn_failed_addr_interval = 5min &redef;
	const conn_failed_port_interval = 5min &redef;

	const default_addr_scan_threshold = 25 &redef;
	const default_port_scan_threshold = 15 &redef;

	# For address scan
	const suppress_UDP_scan_checks  = T &redef;
	const suppress_TCP_scan_checks  = F &redef;
	const suppress_ICMP_scan_checks = T &redef;
	
	global addr_scan_thresh_series: vector of count = vector(100, 200, 300);
	global port_scan_thresh_series: vector of count = vector(10, 20, 30);

	# Custom threholds based on service for address scan
	const addr_scan_custom_thresholds: table[port] of count &redef;
}

function is_failed_conn(c: connection): bool
	{
	# Sr || ( (hR || ShR) && (data not sent in any direction) ) 
	if ( (c$orig$state == TCP_SYN_SENT && c$resp$state == TCP_RESET) ||
	     (
	      ((c$orig$state == TCP_RESET && c$resp$state == TCP_SYN_ACK_SENT) ||
	       (c$orig$state == TCP_RESET && c$resp$state == TCP_ESTABLISHED && "S" in c$history )
	      ) &&
	      !("D" in c$history || "d" in c$history)
	     ) )
		return T;
	return F;
	}

function is_reverse_failed_conn(c: connection): bool
	{
	# reverse scan i.e. conn dest is the scanner
	# sR || ( (Hr || sHr) && (data not sent in any direction) ) 
	if ( (c$resp$state == TCP_SYN_SENT && c$orig$state == TCP_RESET) ||
	     (
	      ((c$resp$state == TCP_RESET && c$orig$state == TCP_SYN_ACK_SENT) ||
	       (c$resp$state == TCP_RESET && c$orig$state == TCP_ESTABLISHED && "s" in c$history )
	      ) &&
	      !("D" in c$history || "d" in c$history)
	     ) )
		return T;
	return F;
	}

function addr_scan_predicate(index: Metrics::Index, data: Metrics::DataPoint): bool
	{
	local service = to_port(index$str);
	local host = index$host;

	local transport_layer_proto = get_port_transport_proto(service);
	if ( suppress_UDP_scan_checks && (transport_layer_proto == udp) )
		return F;
	else if ( suppress_TCP_scan_checks && (transport_layer_proto == tcp) )
		return F;
	else if ( suppress_ICMP_scan_checks && (transport_layer_proto == icmp) )
		return F;

	# TODO: all of this whitelist/blacklist will be done 
	#       through the upcoming hook mechanism
	# Blacklisting/whitelisting services
	#if ( |analyze_services| > 0 )
	#	{
	#	if ( service !in analyze_services )
	#		return F;
	#	}
	#else if ( service in skip_services )
	#	return F;
	#
	## Blacklisting/whitelisting subnets
	#if ( |analyze_subnets| > 0 && host !in analyze_subnets )
	#	return F;

	return T;
	}

function port_scan_predicate(index: Metrics::Index, data: Metrics::DataPoint): bool
	{
	local service = to_port(data$str);
	local host = index$host;

	local transport_layer_proto = get_port_transport_proto(service);
	if ( suppress_UDP_scan_checks && (transport_layer_proto == udp) )
		return F;
	else if ( suppress_TCP_scan_checks && (transport_layer_proto == tcp) )
		return F;
	else if ( suppress_ICMP_scan_checks && (transport_layer_proto == icmp) )
		return F;

	# TODO: all of this whitelist/blacklist will be done 
	#       through the upcoming hook mechanism
	# Blacklisting/whitelisting services
	#if ( |analyze_services| > 0 )
	#	{
	#	if ( service !in analyze_services )
	#		return F;
	#	}
	#else if ( service in skip_services )
	#	return F;
	#
	## Blacklisting/whitelisting subnets
	#if ( |analyze_subnets| > 0 && host !in analyze_subnets )
	#	return F;

	return T;
	}

function check_addr_scan_threshold(index: Metrics::Index, val: Metrics::ResultVal): bool
	{
	local service = to_port(index$str);

	return ( service in addr_scan_custom_thresholds &&
	         val$sum > addr_scan_custom_thresholds[service] );
	}

function addr_scan_threshold_crossed(index: Metrics::Index, val: Metrics::ResultVal)
	{
	local direction = Site::is_local_addr(index$host) ? "OutboundScan" : "InboundScan";
	local message=fmt("%s scanned %d unique hosts on port %s", index$host, val$unique, index$str);

	NOTICE([$note=AddressScan,
	        $src=index$host,
	        $p=to_port(index$str),
	        $sub=direction,
	        $msg=message,
	        $identifier=message]);
	}

function port_scan_threshold_crossed(index: Metrics::Index, val: Metrics::ResultVal)
	{
	local direction = Site::is_local_addr(index$host) ? "OutboundScan" : "InboundScan";
	local message = fmt("%s scanned %d unique ports of host %s", index$host, val$unique, index$str);

	NOTICE([$note=PortScan, 
	        $src=index$host,
	        $dst=to_addr(index$str),
	        $sub=direction,
	        $msg=message,
	        $identifier=message]);
	}

event bro_init() &priority=5
	{
	# Add local networks here to determine scan direction
	# i.e. inbound scan / outbound scan
	#add Site::local_nets[0.0.0.0/16];

	if ( analyze_addr_scan )
		{
		# note=> Addr scan: table [src_ip, port] of set(dst);	
		# Add filters to the metrics so that the metrics framework knows how to
		# determine when it looks like an actual attack and how to respond when
		# thresholds are crossed.
		Metrics::add_filter("scan.addr.fail", [$log=F,
		                                       $every=conn_failed_addr_interval,
		                                       $measure=set(Metrics::UNIQUE),
		                                       $pred=addr_scan_predicate,
		                                       $threshold_func=check_addr_scan_threshold,
		                                       $threshold=default_addr_scan_threshold,
		                                       $threshold_crossed=addr_scan_threshold_crossed]); 
		}

	if ( analyze_port_scan )
		{
		# note=> Port Sweep: table[src_ip, dst_ip] of set(port);
		# Add filters to the metrics so that the metrics framework knows how to
		# determine when it looks like an actual attack and how to respond when
		# thresholds are crossed.
		Metrics::add_filter("scan.port.fail", [$log=F,
		                                       $every=conn_failed_port_interval,
		                                       $measure=set(Metrics::UNIQUE),
		                                       $pred=port_scan_predicate,
		                                       $threshold=default_port_scan_threshold,
		                                       $threshold_crossed=port_scan_threshold_crossed]); 
		}
	}

## Generated when a SYN-ACK packet is seen in response to a SYN 
## packet during a TCP handshake. The final ACK of the handshake 
## in response to SYN-ACK may or may not occur later, one way to 
## tell is to check the history field of connection to see if the 
## originator sent an ACK, indicated by ‘A’ in the history string.
#event connection_established(c: connection)
#	{
	# Not useful for scan (too early)
#	}

## Generated when one endpoint of a TCP connection attempted 
## to gracefully close the connection, but the other endpoint 
## is in the TCP_INACTIVE state. This can happen due to split 
## routing, in which Bro only sees one side of a connection.
#event connection_half_finished(c: connection)
#	{
	# Half connections never were "established", so do scan-checking here.
	# I am not taking *f cases of c$history into account. Ask Seth if I should
#	}

function add_metrics(id: conn_id, reverse: bool)
	{
	local scanner:      addr;
	local victim:       string;
	local scanned_port: string;

	if ( reverse )
		{
		scanner      = id$resp_h;
		victim       = cat(id$orig_h);
		scanned_port = fmt("%s", id$orig_p);
		}
	else
		{
		scanner      = id$orig_h;
		victim       = cat(id$resp_h);
		scanned_port = fmt("%s", id$resp_p);
		}

	if ( analyze_addr_scan )
		Metrics::add_data("scan.addr.fail", [$host=scanner, $str=scanned_port], [$str=victim]);
	if ( analyze_port_scan )
		Metrics::add_data("scan.port.fail", [$host=scanner, $str=victim],       [$str=scanned_port]);
	}

## Generated for an unsuccessful connection attempt. This 
## event is raised when an originator unsuccessfully attempted 
## to establish a connection. “Unsuccessful” is defined as at least 
## tcp_attempt_delay seconds having elapsed since the originator 
## first sent a connection establishment packet to the destination 
## without seeing a reply.
event connection_attempt(c: connection)
	{
	local is_reverse_scan = F;
	if ( "H" in c$history )
		is_reverse_scan = T;
	
	add_metrics(c$id, is_reverse_scan);
	}

## Generated for a rejected TCP connection. This event 
## is raised when an originator attempted to setup a TCP 
## connection but the responder replied with a RST packet 
## denying it.
event connection_rejected(c: connection)
	{
	local is_reverse_scan = F;
	if ( "s" in c$history )
		is_reverse_scan = T;
	
	add_metrics(c$id, is_reverse_scan);
	}

## Generated when an endpoint aborted a TCP connection. 
## The event is raised when one endpoint of an *established* 
## TCP connection aborted by sending a RST packet.
event connection_reset(c: connection)
	{
	local is_reverse_scan = F;
	local is_scan = F;

	if ( is_failed_conn(c) )
		{
		is_scan = T;
		}
	else if ( is_reverse_failed_conn(c) )
		{
		is_scan = T;
		is_reverse_scan = T;
		}

	if ( is_scan )
		{
		add_metrics(c$id, is_reverse_scan);
		}
	}

## Generated for each still-open connection when Bro terminates.
event connection_pending(c: connection)
	{
	local is_reverse_scan = F;
	local is_scan = F;

	if ( is_failed_conn(c) )
		{
		is_scan = T;
		}
	else if ( is_reverse_failed_conn(c) )
		{
		is_scan = T;
		is_reverse_scan = T;
		}

	if ( is_scan )
		{
		add_metrics(c$id, is_reverse_scan);
		}
	}