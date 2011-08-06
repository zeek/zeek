##! Local site policy. Customize as appropriate.

# Load the script to log which script were loaded during each run
@load misc/loaded-scripts

# Apply the default tuning scripts for common tuning settings.
@load tuning/defaults

# Vulnerable versions of software to generate notices for when discovered.
# The default is to only monitor software found in the address space defined
# as "local".  Refer to the software framework's documentation for more information.
@load frameworks/software/vulnerable
redef Software::vulnerable_versions += {
	["Flash"] = [$major=10,$minor=2,$minor2=153,$addl="1"],
	["Java"] = [$major=1,$minor=6,$minor2=0,$addl="22"],
};

# This adds signatures to detect cleartext forward and reverse windows shells.
redef signature_files += "frameworks/signatures/detect-windows-shells.sig";

