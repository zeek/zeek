##! This script adds additional fields corresponding to the RRSIG record responses for the current
##! query to the DNS log. It can cause severe overhead.

@load base/protocols/dns/main
@load base/protocols/dns/consts

module DNS;

export {
        redef record Info += {
                rrsig_type_covered: vector of string   &log &optional;
                rrsig_orig_ttl: vector of interval    &log &optional;
                rrsig_key_tag: vector of count        &log &optional;
                rrsig_algo: vector of string      &log &optional;
                rrsig_labels: vector of count         &log &optional;
                rrsig_signer_name: vector of string   &log &optional;
                rrsig_signature: vector of string     &log &optional;
                rrsig_sig_exp: vector of time         &log &optional;
                rrsig_sig_inc: vector of time         &log &optional;
        };
}

event dns_RRSIG_addl(c: connection, msg: dns_msg, ans: dns_answer, rrsig: dns_rrsig_additional)
        {
        if ( c?$dns )
                {
                if ( ! c$dns?$rrsig_type_covered )
                       c$dns$rrsig_type_covered = vector();
                c$dns$rrsig_type_covered[|c$dns$rrsig_type_covered|] = DNS::query_types[rrsig$type_covered];

                if ( ! c$dns?$rrsig_orig_ttl )
                       c$dns$rrsig_orig_ttl = vector();
                c$dns$rrsig_orig_ttl[|c$dns$rrsig_orig_ttl|] = rrsig$orig_ttl;

                if ( ! c$dns?$rrsig_key_tag )
                       c$dns$rrsig_key_tag = vector();
                c$dns$rrsig_key_tag[|c$dns$rrsig_key_tag|] = rrsig$key_tag;

                if ( ! c$dns?$rrsig_algo )
                       c$dns$rrsig_algo = vector();
                c$dns$rrsig_algo[|c$dns$rrsig_algo|] = DNS::algorithms[rrsig$algorithm];

                if ( ! c$dns?$rrsig_labels )
                       c$dns$rrsig_labels = vector();
                c$dns$rrsig_labels[|c$dns$rrsig_labels|] = rrsig$labels;

                if ( ! c$dns?$rrsig_signer_name )
                       c$dns$rrsig_signer_name = vector();
                c$dns$rrsig_signer_name[|c$dns$rrsig_signer_name|] = rrsig$signer_name;

                if ( ! c$dns?$rrsig_signature )
                       c$dns$rrsig_signature = vector();
                c$dns$rrsig_signature[|c$dns$rrsig_signature|] = bytestring_to_hexstr(rrsig$signature);

                if ( ! c$dns?$rrsig_sig_exp )
                       c$dns$rrsig_sig_exp = vector();
                c$dns$rrsig_sig_exp[|c$dns$rrsig_sig_exp|] = rrsig$sig_exp;

                if ( ! c$dns?$rrsig_sig_inc )
                       c$dns$rrsig_sig_inc = vector();
                c$dns$rrsig_sig_inc[|c$dns$rrsig_sig_inc|] = rrsig$sig_incep;
                }

        }
