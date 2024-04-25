# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: cat ssh.spicy ssh-1.spicy > ssh-test.spicy
# @TEST-EXEC: spicyz -d -o test.hlto ssh-test.spicy ./ssh-cond.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT Spicy::enable_print=T 2>&1 | sort  >output-1
#
# @TEST-EXEC: cat x509.log | grep -v ^# | cut -f 4-5 >x509.log.tmp && mv x509.log.tmp x509.log
# @TEST-EXEC: btest-diff x509.log
#
# @TEST-EXEC: cat files.log | zeek-cut sha1 filename >files.log.tmp && mv files.log.tmp files.log
# @TEST-EXEC: btest-diff files.log
#
# @TEST-EXEC: cat ssh.spicy ssh-2.spicy > ssh-test.spicy
# @TEST-EXEC: spicyz -d -o test.hlto ssh-test.spicy ./ssh-cond.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT Spicy::enable_print=T 2>&1  | sort  >output-2
#
# @TEST-EXEC: cat files.log | zeek-cut fuid filename >files.log.tmp && mv files.log.tmp files-2.log
# @TEST-EXEC: btest-diff files-2.log
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-canonifier-spicy btest-diff output-1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-canonifier-spicy btest-diff output-2

module SSH;

function get_file_handle(c: connection, is_orig: bool): string
	{
	print "get_file_handle called";
	return cat(c$uid);
	}

event zeek_init()
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_SPICY_SSH, 22/tcp);
	Files::register_protocol(Analyzer::ANALYZER_SSH, [$get_file_handle=SSH::get_file_handle]); # use tag of replaced analyzer
	}

# @TEST-START-FILE ssh.spicy
module SSH;

import spicy;
import zeek;

global file_counter = 0;

public type Banner = unit {
    magic   : /SSH-/ {
	# This is a bit of cheating.
	local d: spicy::Base64Stream;
	local dec : bytes = spicy::base64_decode(d, b"MIIESjCCAzKgAwIBAgINAeO0mqGNiqmBJWlQuDANBgkqhkiG9w0BAQsFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNzA2MTUwMDAwNDJaFw0yMTEyMTUwMDAwNDJaMEIxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVHb29nbGUgVHJ1c3QgU2VydmljZXMxEzARBgNVBAMTCkdUUyBDQSAxTzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQGM9F1IvN05zkQO9+tN1pIRvJzzyOTHW5DzEZhD2ePCnvUA0Qk28FgICfKqC9EksC4T2fWBYk/jCfC3R3VZMdS/dN4ZKCEPZRrAzDsiKUDzRrmBBJ5wudgzndIMYcLe/RGGFl5yODIKgjEv/SJH/UL+dEaltN11BmsK+eQmMF++AcxGNhr59qM/9il71I2dN8FGfcddwuaej4bXhp0LcQBbjxMcI7JP0aM3T4I+DsaxmKFsbjzaTNC9uzpFlgOIg7rR25xoynUxv8vNmkq7zdPGHXkxWY7oG9j+JkRyBABk7XrJfoucBZEqFJJSPk7XA0LKW0Y3z5oz2D0c1tJKwHAgMBAAGjggEzMIIBLzAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFJjR+G4Q68+b7GCfGJAboOt9Cf0rMB8GA1UdIwQYMBaAFJviB1dnHB7AagbeWbSaLd/cGYYuMDUGCCsGAQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AucGtpLmdvb2cvZ3NyMjAyBgNVHR8EKzApMCegJaAjhiFodHRwOi8vY3JsLnBraS5nb29nL2dzcjIvZ3NyMi5jcmwwPwYDVR0gBDgwNjA0BgZngQwBAgIwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly9wa2kuZ29vZy9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAGoA+Nnn78y6pRjd9XlQWNa7HTgiZ/r3RNGkmUmYHPQq6Scti9PEajvwRT2iWTHQr02fesqOqBY2ETUwgZQ+lltoNFvhsO9tvBCOIazpswWC9aJ9xju4tWDQH8NVU6YZZ/XteDSGU9YzJqPjY8q3MDxrzmqepBCf5o8mw/wJ4a2G6xzUr6Fb6T8McDO22PLRL6u3M4Tzs3A2M1j6bykJYi8wWIRdAvKLWZu/axBVbzYmqmwkm5zLSDW5nIAJbELCQCZwMH56t2Dvqofxs6BBcCFIZUSpxu6x6td0V7SvJCCosirSmIatj/9dSSVDQibet8q/7UK4v4ZUN80atnZz1yg==");
	dec += spicy::base64_finish(d);

	print self.file_id;
	zeek::file_data_in(dec);
    }
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;

    var file_id: string;
    var file_name: string = "foo-%d.txt" % ++file_counter;
};

on Banner::%done { zeek::file_end(self.file_id); }

# @TEST-END-FILE

# First test case - just let Zeek generate the File ID
# @TEST-START-FILE ssh-1.spicy

on Banner::%init { self.file_id = zeek::file_begin("application/x-x509-ca-cert"); }

# @TEST-END-FILE ssh-1.spicy

# Second test case - provide a file ID
# @TEST-START-FILE ssh-2.spicy

on Banner::%init { self.file_id = zeek::file_begin("application/x-x509-ca-cert", "FaAaAaAaAaAaAaAaAa"); }

# @TEST-END-FILE ssh-2.spicy

# @TEST-START-FILE ssh-cond.evt

import zeek;

protocol analyzer spicy::SSH over TCP:
    parse with SSH::Banner,
    replaces SSH;

on SSH::Banner::software -> event have_filename($file, self.file_name);

# @TEST-END-FILE

# Trigger creation of `files.log`.
@load base/protocols/ssl
redef X509::log_x509_in_files_log = T;

event have_filename(f: fa_file, filename: string)
	{
	f$info$filename = filename;
	}
