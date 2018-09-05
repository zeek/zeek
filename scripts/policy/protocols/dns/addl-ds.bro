##! This script adds additional fields for the DS dns response of current
##! query to the DNS log.  It can cause severe overhead.

@load base/protocols/dns/main
@load base/protocols/dns/consts

redef dns_skip_all_auth = F;
redef dns_skip_all_addl = F;

module DNS;

export {
        redef record Info += {

        ds_key_tag:     vector of count &log &optional;
        ds_algo:        vector of string        &log &optional;
        ds_digestType:  vector of string        &log &optional;
        ds_digest:      vector of string        &log &optional;
        };
}

event dns_DS_addl(c: connection, msg: dns_msg, ans: dns_answer, ds: dns_ds_additional)
        {
        if ( c?$dns )
                {
                if ( ! c$dns?$ds_key_tag )
                       c$dns$ds_key_tag = vector();
                c$dns$ds_key_tag[|c$dns$ds_key_tag|] = ds$key_tag;

                if ( ! c$dns?$ds_algo )
                       c$dns$ds_algo = vector();
                c$dns$ds_algo[|c$dns$ds_algo|] = DNS::algorithms[ds$algorithm];

                if ( ! c$dns?$ds_digestType )
                       c$dns$ds_digestType = vector();
                c$dns$ds_digestType[|c$dns$ds_digestType] = DNS::digests[ds$digest_type];

                if ( ! c$dns?$ds_digest)
                       c$dns$ds_digest = vector();
                c$dns$ds_digest[|c$dns$ds_digest|] = bytestring_to_hexstr(ds$digest_val);
                }
        }
