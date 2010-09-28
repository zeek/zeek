# series of functions to be used by the signatures
#

# we see *allot* of odd patch related traffic to and from M$
const  MS_ADDR_RANGE: set[subnet] &redef;
redef MS_ADDR_RANGE = { 207.46.0.0/16 };

# the following are all based on the existance of software.bro
# being loaded
@ifdef ( software_table )
function isApache(state: signature_state): bool
        {
        local ip = state$conn$id$resp_h;

        if ( ip !in software_table )
                return F;

        local softset = software_table[ip];

        if ( "Apache" !in softset )
                return F;

        return T;
        }

function isApacheLt12(state: signature_state): bool
        {
        local ip = state$conn$id$resp_h;
                                                                                                                                            
        if ( ip !in software_table )
                return F;
                                                                                                                                            
        local softset = software_table[ip];

        if ( "Apache" !in softset )
                return F;
		
        local safe_version: software_version =
                [$major = +1, $minor = +2, $minor2 = +0, $addl = ""];

        if ( software_cmp_version(softset["Apache"]$version, safe_version) >= 0 )
                return F;
 
        return T;
        }

function isApacheLt1322(state: signature_state): bool
        {
        local ip = state$conn$id$resp_h;
                                                                                               
                                                                                               
        if ( ip !in software_table )
                return F;
                                                                                               
                                                                                               
        local softset = software_table[ip];
        
        if ( "Apache" !in softset )
                return F;
		
        local safe_version: software_version =
                [$major = +1, $minor = +3, $minor2 = -22, $addl = ""];
                                                                                               
        if ( software_cmp_version(softset["Apache"]$version, safe_version) >= 0 )
                return F;
                                                                                               
        return T;
        }

function isApacheLt1325(state: signature_state): bool
        {
        local ip = state$conn$id$resp_h;
                                                                                               
                                                                                               
        if ( ip !in software_table )
                return F;
                                                                                               
                                                                                               
        local softset = software_table[ip];
                                                                                               
        if ( "Apache" !in softset )
                return F;
		
        local safe_version: software_version =
                [$major = +1, $minor = +3, $minor2 = -25, $addl = ""];
                                                                                               
        if ( software_cmp_version(softset["Apache"]$version, safe_version) >= 0 )
                return F;
                                                                                               
        return T;
        }



function isNotApache(state: signature_state): bool
        {
        local ip = state$conn$id$resp_h;
 
        if ( ip !in software_table )
                return F;
 
        local softset = software_table[ip];
 
        if ( "Apache" !in softset )
                return T;

        return F;
        }


function isIIS(state: signature_state): bool
        {
        local ip = state$conn$id$resp_h;
 
        if ( ip !in software_table )
                return F;
 
        local softset = software_table[ip];
 
        if ( "IIS" !in softset )
                return F;

        return T;
        }

function isNotIIS(state: signature_state): bool
        {
        local ip = state$conn$id$resp_h;
 
        if ( ip !in software_table )
                return F;
 
        local softset = software_table[ip];
 
        if ( "IIS" !in softset )
                return T;
 
        return F;
        }

function isMSIE(state: signature_state): bool
        {
        local ip = state$conn$id$resp_h;
 
        if ( ip !in software_table )
                return F;
 
        local softset = software_table[ip];
 
        if ( "MSIE" !in softset )
                return F;
 
        return T;
        }

function isNotMSIE(state: signature_state): bool
        {
        local ip = state$conn$id$resp_h;

        if ( ip !in software_table )
                return F;

        local softset = software_table[ip];

        if ( "MSIE" !in softset )
                return T;

        return F;
        }


function isMozilla(state: signature_state): bool
        {
        local ip = state$conn$id$resp_h;

        if ( ip !in software_table )
                return F;

        local softset = software_table[ip];

        if ( "Mozilla" !in softset )
                return F;

        return T;
        }

function isNotMozilla(state: signature_state): bool
        {
        local ip = state$conn$id$resp_h;

        if ( ip !in software_table )
                return F;

        local softset = software_table[ip];

        if ( "Mozilla" !in softset )
                return T;

        return F;
        }

function isRealMedia(state: signature_state): bool
        {
        local ip = state$conn$id$resp_h;

        if ( ip !in software_table )
                return F;

        local softset = software_table[ip];

        if ( "Mozilla" !in softset )
                return F;

        return T;
        }


@endif
# end of the software.bro related functions

function dataSizeG50(state: signature_state): bool
	{
	local size = state$payload_size;

	if ( size < 50 )
		return F;

	return T;
	}

function dataSizeG100(state: signature_state): bool
        {
        local size = state$payload_size;

        if ( size < 100 )
                return F;

        return T;
        }

function dataSizeG150(state: signature_state): bool
        {
        local size = state$payload_size;

        if ( size < 150 )
                return F;

        return T;
        }


function dataSizeG200(state: signature_state): bool
        {
        local size = state$payload_size;

        if ( size < 200 )
                return F;

        return T;
        }



function respInMsNet(state: signature_state): bool
        {
	local ip = state$conn$id$resp_h;

	return ip in MS_ADDR_RANGE;
	}


function origInMsNet(state: signature_state): bool
        {
        local ip = state$conn$id$orig_h;
                                                                                                                              
        return ip in MS_ADDR_RANGE;
        }

