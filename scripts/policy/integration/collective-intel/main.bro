
module Intel;

## These are some fields to add extended compatibility between Bro and the Collective
## Intelligence Framework: http://code.google.com/p/collective-intelligence-framework/
redef record Intel::MetaData += {
	cif_impact:     string &optional;
	## Maps to the Severity field in the Collective Intelligence Framework.
	cif_severity:   string &optional;
	## Maps to the Confidence field in the Collective Intelligence Framework.
	cif_confidence: double &optional;
};