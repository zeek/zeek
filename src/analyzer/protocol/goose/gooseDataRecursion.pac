## This file is a workaround for the circular record dependency issue.
## It enables BinPAC to generate a parser for the field "allData" of
## "goosePdu" despite its potential recursivity.

%include goose-protocol.pac

## The cases creating a circular dependency within the definition of GOOSEData
## are isolated here as a refine casetype.
refine casetype GOOSEDataContent += {
	ARRAY -> array: GOOSEData[] &length=size &until($input.length() == 0);
	STRUCTURE -> structure: GOOSEData[] &length=size &until($input.length() == 0);
};
