
@load misc/stats
@load misc/app-stats

# Scripts that do asset tracking.
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/dhcp/known-devices-and-hostnames
@load protocols/dns/detect-external-names
@load protocols/ssl/known-certs

# This adds signatures to detect cleartext forward and reverse windows shells.
@load-sigs frameworks/signatures/detect-windows-shells

@load protocols/ssl/validate-certs

# Enable MD5 and SHA1 hashing for all files.
@load frameworks/files/hash-all-files

# disable ASCII logging
redef Log::enable_local_logging = F;

# enable broccoli
@load frameworks/communication/listen

redef Communication::listen_port = 47758/tcp;
redef Communication::nodes += {
	["msmiley"] = [$host = 127.0.0.1, $connect=F, $ssl=F]
};

# assume all private nets are local
redef Site::local_nets = {
	10.0.0.0/8,
	192.168.0.0/16,
	172.16.0.0/12,
	100.64.0.0/10,  # RFC6598 Carrier Grade NAT
	127.0.0.0/8,
	[fe80::]/10,# disable IPV6 for the time being
	[::1]/128,# disable IPV6 for the time being
};
