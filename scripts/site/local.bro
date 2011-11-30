##! Local site policy. Customize as appropriate. This file will not be 
##! overwritten when upgrading or reinstalling.

# Load the script to log which script were loaded during each run
@load misc/loaded-scripts

# Apply the default tuning scripts for common tuning settings.
@load tuning/defaults

# Vulnerable versions of software to generate notices for when discovered.
# The default is to only monitor software found in the address space defined
# as "local".  Refer to the software framework's documentation for more 
# information.
@load frameworks/software/vulnerable
redef Software::vulnerable_versions += {
	["Flash"] = [$major=10,$minor=2,$minor2=153,$addl="1"],
	["Java"] = [$major=1,$minor=6,$minor2=0,$addl="22"],
};

# This adds signatures to detect cleartext forward and reverse windows shells.
redef signature_files += "frameworks/signatures/detect-windows-shells.sig";

# Uncomment the following line to begin receiving (by default hourly) emails
# containing all of your notices.
# redef Notice::policy += { [$action = Notice::ACTION_ALARM, $priority = 0] };

# Load all of the scripts that detect software in various protocols.
@load protocols/http/software
#@load protocols/http/detect-webapps
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software

# Load the script to detect DNS results pointing toward your Site::local_nets 
# where the name is not part of your local DNS zone and is being hosted 
# externally.  Requires that the Site::local_zones variable is defined.
@load protocols/dns/detect-external-names

# Script to detect various activity in FTP sessions.
@load protocols/ftp/detect

# Detect software changing (e.g. attacker installing hacked SSHD).
@load frameworks/software/version-changes

# Scripts that do asset tracking.
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs

# Load the script to enable SSL/TLS certificate validation.
@load protocols/ssl/validate-certs

# If you have libGeoIP support built in, do some geographic detections and 
# logging for SSH traffic.
@load protocols/ssh/geo-data
# Detect hosts doing SSH bruteforce attacks.
@load protocols/ssh/detect-bruteforcing
# Detect logins using "interesting" hostnames.
@load protocols/ssh/interesting-hostnames

# Detect MD5 sums in Team Cymru's Malware Hash Registry.
@load protocols/http/detect-MHR
# Detect SQL injection attacks
@load protocols/http/detect-sqli

# Uncomment this redef if you want to extract SMTP MIME entities for 
# some file types.  The numbers given indicate how many bytes to extract for
# the various mime types.
@load base/protocols/smtp/entities-excerpt
redef SMTP::entity_excerpt_len += {
#	["text/plain"] = 1024,
#	["text/html"] = 1024,
};
