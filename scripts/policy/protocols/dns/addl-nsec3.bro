##! This script adds additional fields for the NSEC3 dns response of current
##! query to the DNS log.  It can cause severe overhead.

@load base/protocols/dns/main
@load base/protocols/dns/consts

redef dns_skip_all_auth = F;
redef dns_skip_all_addl = F;

module DNS;

export {
        redef record Info += {

        insec_flags:    vector of count &log &optional;
        nsec_hash_algo: vector of count &log &optional;
        nsec_iter:      vector of count &log &optional;
        nsec_salt_len:  vector of count &log &optional;
        nsec_salt:      vector of string        &log &optional;
        nsec_hlen:      vector of count &log &optional;
        nsec_hash:      vector of string        &log &optional;
        nsec_bitmaps:   vector of string        &log &optional;
        };
}

event dns_NSEC3_addl(c: connection, msg: dns_msg, ans: dns_answer, nsec3: dns_nsec3_additional, bitmaps: string_vec)
        {
        if ( c?$dns )
                {
                if ( ! c$dns?$nsec_flags )
                       c$dns$nsec_flags = vector();
                c$dns$nsec_flags[|c$dns$nsec_flags|] = nsec3$nsec_flags;

                if ( ! c$dns?$nsec_hash_algo )
                       c$dns$nsec_hash_algo = vector();
                c$dns$nsec_hash_algo[|c$dns$nsec_hash_algo|] = nsec3$nsec_hash_algo;

                if ( ! c$dns?$nsec_iter )
                       c$dns$nsec_iter = vector();
                c$dns$nsec_iter[|c$dns$nsec_iter|] = nsec3$nsec_iter;

                if ( ! c$dns?$nsec_salt_len)
                       c$dns$nsec_salt_len = vector();
                c$dns$nsec_salt_len[|c$dns$nsec_salt_len|] = nsec3$nsec_salt_len;

                if ( ! c$dns?$nsec_salt)
                       c$dns$nsec_salt = vector();
                c$dns$nsec_salt[|c$dns$nsec_salt] = bytestring_to_hexstr(nsec3$nsec_salt);

                 if ( ! c$dns?$nsec_hlen)
                       c$dns$nsec_hlen = vector();
                c$dns$nsec_hlen[|c$dns$nsec_hlen|] = nsec3$nsec_hlen;

                if ( ! c$dns?$nsec_hash)
                       c$dns$nsec_hash = vector();
                c$dns$nsec_hash[|c$dns$nsec_hash] = bytestring_to_hexstr(nsec3$nsec_hash);

                if ( ! c$dns?$nsec_bitmaps)
                       c$dns$nsec_bitmaps = vector();

                if ( |bitmaps| != 0)
                  {
                        local bitmap_strings: string = "";

                        for ( i in bitmaps )
                        {
                           if ( i > 0 )
                                bitmap_strings += " ";

                           bitmap_strings += fmt("bitmap %d %s", |bitmaps[i]|, bitmaps[i]);
                        }
                        c$dns$nsec_bitmaps[|c$dns$nsec_bitmaps] = bitmap_strings;
                  }

                }
        }
