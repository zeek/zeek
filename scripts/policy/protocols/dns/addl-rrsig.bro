##! This script adds additional fields corresponding to the RRSIG record responses for the current
##! query to the DNS log. 

@load base/protocols/dns/main
@load base/protocols/dns/consts

module DNS;

export {
        redef record Info += {
                type_covered: vector of string   &log &optional;
                orig_ttl: vector of interval    &log &optional;
                key_tag: vector of count        &log &optional;
                algorithm: vector of string      &log &optional;
                labels: vector of count         &log &optional;
                signer_name: vector of string   &log &optional;
                signature: vector of string     &log &optional;
                sig_exp: vector of time         &log &optional;
                sig_inc: vector of time         &log &optional;
        };
}

event dns_RRSIG_addl(c: connection, msg: dns_msg, ans: dns_answer, rrsig: dns_rrsig_additional)
        {
        if ( c?$dns )

                if ( ! c$dns?$type_covered )
                       c$dns$type_covered = vector();
                c$dns$type_covered[|c$dns$type_covered|] = query_types[rrsig$type_covered];

                if ( ! c$dns?$orig_ttl )
                       c$dns$orig_ttl = vector();
                c$dns$orig_ttl[|c$dns$orig_ttl|] = rrsig$orig_ttl;

                if ( ! c$dns?$key_tag )
                       c$dns$key_tag = vector();
                c$dns$key_tag[|c$dns$key_tag|] = rrsig$key_tag;

                if ( ! c$dns?$algorithm )
                       c$dns$algorithm = vector();
                c$dns$algorithm[|c$dns$algorithm|] = algorithms[rrsig$algorithm];

                if ( ! c$dns?$labels )
                       c$dns$labels = vector();
                c$dns$labels[|c$dns$labels|] = rrsig$labels;

                if ( ! c$dns?$signer_name )
                       c$dns$signer_name = vector();
                c$dns$signer_name[|c$dns$signer_name|] = rrsig$signer_name;

                if ( ! c$dns?$signature )
                       c$dns$signature = vector();
                c$dns$signature[|c$dns$signature|] = bytestring_to_hexstr(rrsig$signature);

                if ( ! c$dns?$sig_exp )
                       c$dns$sig_exp = vector();
                c$dns$sig_exp[|c$dns$sig_exp|] = rrsig$sig_exp;

                if ( ! c$dns?$sig_inc )
                       c$dns$sig_inc = vector();
                c$dns$sig_inc[|c$dns$sig_inc|] = rrsig$sig_incep;

        }
