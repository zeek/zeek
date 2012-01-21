
module SSL;

export {
    ## Extracts the attribute value of an ASN.1 string. The format of *str* is
    ## specified in RFC 2253. This function correctly parses multi-valued
    ## relative distinguished names (RDNs).
    ##
    ## For example, one may use this function to extract the CN value of the
    ## SSL certificate subject.
    ##
    ## str: The ASN.1 string.
    ##
    ## attr: The attribute to extract.
    ##
    ## Returns: The value associated with *attr* or the empty string if *attr*
    ##          does not exist in *str*.
    ##
    ## .. note::
    ##
    ##      This function does not consider the variations of RFC 1779 and
    ##      LDAPv2 discussed in section 4 of RFC 2253.
    global extract_asn1_value: function(str: string, attr: string): string;
}

function extract_asn1_value(str: string, attr: string): string
    {
    local rdns = split(str, /[^\\],/);
    for ( i in rdns )
        {
        # Multi-valued RDN are separated by the '+' character.
        local mv_rdns = split(strip(rdns[i]), /[^\\]\+/);
        for ( j in mv_rdns )
            {
            local pair = split(mv_rdns[j], /=/);
            if ( attr == pair[1] )
                return pair[2];
            }
        }

    return "";
    }

