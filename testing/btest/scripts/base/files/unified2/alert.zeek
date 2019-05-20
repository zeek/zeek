# @TEST-EXEC: zeek -b %INPUT Unified2::watch_file=$FILES/unified2.u2
# @TEST-EXEC: btest-diff unified2.log

@TEST-START-FILE sid_msg.map
2003058 || ET MALWARE 180solutions (Zango) Spyware Installer Download || url,doc.emergingthreats.net/bin/view/Main/2003058 || url,securityresponse.symantec.com/avcenter/venc/data/pf/adware.180search.html
2012647 || ET POLICY Dropbox.com Offsite File Backup in Use || url,dereknewton.com/2011/04/dropbox-authentication-static-host-ids/ || url,www.dropbox.com
@TEST-END-FILE

@TEST-START-FILE gen_msg.map
1 || 1 || snort general alert
2 || 1 || tag: Tagged Packet
3 || 1 || snort dynamic alert
100 || 1 || spp_portscan: Portscan Detected
100 || 2 || spp_portscan: Portscan Status
100 || 3 || spp_portscan: Portscan Ended
101 || 1 || spp_minfrag: minfrag alert
@TEST-END-FILE

@TEST-START-FILE classification.config
#
# config classification:shortname,short description,priority
#

#Traditional classifications. These will be replaced soon

config classification: not-suspicious,Not Suspicious Traffic,3
config classification: unknown,Unknown Traffic,3
config classification: bad-unknown,Potentially Bad Traffic, 2
config classification: attempted-recon,Attempted Information Leak,2
config classification: successful-recon-limited,Information Leak,2
config classification: successful-recon-largescale,Large Scale Information Leak,2
config classification: attempted-dos,Attempted Denial of Service,2
config classification: successful-dos,Denial of Service,2
config classification: attempted-user,Attempted User Privilege Gain,1
config classification: unsuccessful-user,Unsuccessful User Privilege Gain,1
config classification: successful-user,Successful User Privilege Gain,1
config classification: attempted-admin,Attempted Administrator Privilege Gain,1
config classification: successful-admin,Successful Administrator Privilege Gain,1
config classification: rpc-portmap-decode,Decode of an RPC Query,2
config classification: shellcode-detect,Executable Code was Detected,1
config classification: string-detect,A Suspicious String was Detected,3
config classification: suspicious-filename-detect,A Suspicious Filename was Detected,2
config classification: suspicious-login,An Attempted Login Using a Suspicious Username was Detected,2
config classification: system-call-detect,A System Call was Detected,2
config classification: tcp-connection,A TCP Connection was Detected,4
config classification: trojan-activity,A Network Trojan was Detected, 1
config classification: unusual-client-port-connection,A Client was Using an Unusual Port,2
config classification: network-scan,Detection of a Network Scan,3
config classification: denial-of-service,Detection of a Denial of Service Attack,2
config classification: non-standard-protocol,Detection of a Non-Standard Protocol or Event,2
config classification: protocol-command-decode,Generic Protocol Command Decode,3
config classification: web-application-activity,Access to a Potentially Vulnerable Web Application,2
config classification: web-application-attack,Web Application Attack,1
config classification: misc-activity,Misc activity,3
config classification: misc-attack,Misc Attack,2
config classification: icmp-event,Generic ICMP event,3
config classification: inappropriate-content,Inappropriate Content was Detected,1
config classification: policy-violation,Potential Corporate Privacy Violation,1
config classification: default-login-attempt,Attempt to Login By a Default Username and Password,2
@TEST-END-FILE

redef exit_only_after_terminate = T;

@load base/files/unified2

redef Unified2::sid_msg = @DIR+"/sid_msg.map";
redef Unified2::gen_msg = @DIR+"/gen_msg.map";
redef Unified2::classification_config = @DIR+"/classification.config";
global i = 0;

event Unified2::alert(f: fa_file, ev: Unified2::IDSEvent, pkt: Unified2::Packet)
	{
	++i;
	if ( i == 2 )
		terminate();
	}