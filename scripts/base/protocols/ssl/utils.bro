
module SSL;

export {
    ## Splits a ASN.1 Distinguished Name string into attribute-value pairs. The
    ## format of *str* is ## specified in RFC 2253. This function parses
    ## multi-valued relative distinguished names (RDNs) by associating a single
    ## key with each RDN. For example, parsing the the string:
    ##
    ##    OU=Sales+CN=J. Smith,O=Widget Inc.,C=US
    ##
    ## would result in a table with the keys ``OU``,``CN``,``O``, and ``C``.
    ##
    ## One may use this function to extract the CN value of the SSL
    ## certificate subject or issuer.
    ##
    ## str: The ASN.1 distinguished name.
    ##
    ## Returns: A table that maps the DN attributes to their corresponding
    ##          values.
    ##
    ## .. note::
    ##
    ##      This function does not consider the variations of RFC 1779 and
    ##      LDAPv2 discussed in section 4 of RFC 2253.
    global split_dn: function(str: string): table[string] of string;
}

function split_dn(str: string): table[string] of string
    {
    local result: table[string] of string;
    local rdns = split_esc(str, /,/, "\\");
    for ( i in rdns )
        {
        # Multi-valued RDN are separated by the '+' character.
        local mv_rdns = split_esc(strip(rdns[i]), /\+/, "\\");
        for ( j in mv_rdns )
            {
            local pair = split(mv_rdns[j], /=/);
            result[pair[1]] = pair[2];
            }
        }

    return result;
    }
