##! This script adds additional fields for the DNSKEY dns response of current
##! query to the DNS log.  It can cause severe overhead.

@load base/protocols/dns/main
@load base/protocols/dns/consts

redef dns_skip_all_auth = F;
redef dns_skip_all_addl = F;

module DNS;

export {
        redef record dns += {

        dnskey_flags:   vector of count &log &optional;
        dnskey_algo:    vector of string        &log &optional;
        dnskey_proto:   vector of count &log &optional;
        dnskey_pubkey:  vector of string        &log &optional;
        };
}

event dns_DNSKEY_addl(c: connection, msg: dns_msg, ans: dns_answer, dnskey: dns_dnskey_additional)
        {
        if ( c?$dns )
                {
                if ( ! c$dns?$dnskey_flags )
                       c$dns$dnskey_flags = vector();
                c$dns$dnskey_flags[|c$dns$dnskey_flags|] = dnskey$flags;

                if ( ! c$dns?$dnskey_algo )
                       c$dns$dnskey_algo = vector();
                c$dns$dnskey_algo[|c$dns$dnskey_algo|] = algorithms[dnskey$algorithm];

                if ( ! c$dns?$dnskey_proto )
                       c$dns$dnskey_proto = vector();
                c$dns$dnskey_proto[|c$dns$dnskey_proto|] = dnskey$protocol;

                if ( ! c$dns?$dnskey_pubkey)
                       c$dns$dnskey_pubkey = vector();
                c$dns$dnskey_pubkey[|c$dns$dnskey_pubkey|] = bytestring_to_hexstr(dnskey$public_key);
                }
        }
