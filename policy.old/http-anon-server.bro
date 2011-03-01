# $Id:$

# Anonymize values in Server: headers.
#
# TODO:
#
# - Zedo and IBM web servers can have Apache mods -- the parsing should
#   be extended to support them
#

@load anon
@load http-anon-utils

# ---------------------------------------------------------------------
#                      Apache (and friends)
# - abandon all hope ye who enter here .....
# ---------------------------------------------------------------------

const apache_server =
	/apache(-ish)?(\/([0-9]+\.)*[0-9]+)? *(\(?(red hat( linux)?|cobalt|suse\/linux|linux\/suse|darwin|gentoo\/linux|debian gnu\/linux|win32|fedora|freebsd|red-hat\/linux|unix)\)? *)*/;

const apache_mod_pat =
	  /mod_fastcgi\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /openssl\/([0-9]+\.)*[0-9a-z]{1,4}(-beta[0-9]{0,2})?/
	| /dav\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /php-cgi\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /ben-ssl\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /embperl\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /mod_ruby\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /nexadesic\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /postgresql\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /mod_tsunami\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /mod_auth_svn\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /mod_auth_mda\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /rus\/pl(([0-9]+\.)*[0-9]{1,4})/
	| /authmysql\/(([0-9]+\.)*[0-9]{1,4})/
	| /mod_auth_pgsql\/(([0-9]+\.)*[0-9]{1,4})/
	| /mod_ssl\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /php\/(([0-9]+\.)*[0-9a-z]{1,4})(-[0-9]+)?/
	| /mod_perl\/(([0-9]+\.)*[0-9a-z]{1,4})(\_[0-9]+)?/
	| /mod_macro\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /mod_auth_pam\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /mod_oas\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /mod_cap\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /powweb\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /mod_gzip\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /resin\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /mod_jk\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /python\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /perl\/(v)?(([0-9]+\.)*[0-9a-z]{1,4})/
	| /mod_python\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /mod_log_bytes\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /mod_auth_passthrough\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /mod_bwlimited\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /mod_throttle\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /mod_webapp\/(([0-9]+\.)*[0-9a-z]{1,4})(-dev)?/
	| /frontpage\/(([0-9]+\.)*[0-9a-z]{1,5})/
	| /mod_pubcookie\/[0-9a-z]{2}\/[0-9]+\.[0-9]+\-[0-9]+/
	| /(-)?coyote\/(([0-9]+\.)*[0-9a-z]{1,4})/
	| /svn\/(([0-9]+\.)*[0-9a-z]{1,4})/
	;

# Various Apache variants (e.g., stronghold).
const apache_misc =
	/stronghold\/(([0-9]+\.)*[0-9]+) apache(\/([0-9]+\.)*[0-9]+)? (c2neteu\/[0-9])? *(\(?(red hat( linux)?|cobalt|suse\/linux|linux\/suse|darwin|gentoo\/linux|debian gnu\/linux|win32|fedora|freebsd|red-hat\/linux|unix)\)? *)*/;

const apache_basic = /apache?(\/([0-9]+\.)*[0-9]+)?/;
const apache_platforms =
	/(\(?(red hat( linux)?|cobalt|suse\/linux|linux\/suse|darwin|gentoo\/linux|debian gnu\/linux|win32|fedora|freebsd|red-hat\/linux|unix)\)? *)*/;

# ibm_http_server/1.3.26.2, apache/1.3.26 (unix).
const IBM_server =
	/ibm_http_server(\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)?( *apache\/[0-9]+\.[0-9]+\.[0-9]+ \(unix\))?/;


# ---------------------------------------------------------------------
#  Servers values for which we don't retain all values.
# ---------------------------------------------------------------------

const zope_server =
	/zope\/\(zope ([0-9]+\.)*[0-9]+-[a-z0-9]{1,2}\, python ([0-9]+\.)*[0-9]+\, linux[0-9]\)/;

const thttp_server = /thttpd\/[0-9]+\.[0-9]+(beta[0-9]+)?/;
const weblogic_server = /weblogic server [0-9]+\.[0-9]+/;
const zedo_server = /zedo 3g(\/([0-9]+\.)*[0-9]+)?/;
const jetty_server = /jetty\/[0-9]+\.[0-9]+/;

# ---------------------------------------------------------------------
#                      Misc         Servers
# ---------------------------------------------------------------------

const misc_server =
	  /dclk creative/
	| /gws\/[0-9]+\.[0-9]+/
	| /nfe\/[0-9]+\.[0-9]+/
	| /gfe\/[0-9]+\.[0-9]+/
	| /dclk-adsvr/
	| /rsi/
	| /swcd\/([0-9]+\.)*[0-9]+/
	| /microsoft-iis\/[0-9]{1,2}\.[0-9]{1,2}/
	| /cafe\/[0-9]+\.[0-9]+/
	| /artblast\/([0-9]+\.)*[0-9]+/
	| /aolserver\/([0-9]+\.)*[0-9]+/
	| /resin\/([0-9]+\.)*s?[0-9]+/
	| /netscape-enterprise\/([0-9]+\.)*[0-9a-z]{1,2}+ *(aol)?/
	| /mapquest listener/
	| /miixpc\/[0-9]+\.[0-9]+/
	| /sun-one-web-server\/[0-9]+\.[0-9]+/
	| /appledotmacserver/
	| /cj\/[0-9]+\.[0-9]+/
	| /jigsaw\/([0-9]+\.)*[0-9]+/
	| /boa\/[0-9]+\.[0-9]+(\.[0-9]+(rc[0-9]+)?)?/
	| /tux\/[0-9]+\.[0-9]+ *\(linux\)/
	| /igfe/
	| /trafficmarketplace-jforce\/([0-9]+\.)*[0-9]+/
	| /lighttpd/
	| /hitbox gateway ([0-9]+\.)*[0-9]+ [a-z][0-9]/
	| /jbird\/[0-9]+\.[0-9a-z]{1,2}/
	| /perlbal/
	| /big-ip/
	| /konichiwa\/[0-9]+\.[0-9]+/
	| /footprint [0-9]+\.[0-9]+\/fpmc/
	| /iii [0-9]+/
	| /clickability web server\/([0-9]+\.)*[0-9]+ *\(unix\)/
	| /accipiter-directserver\/([0-9]+\.)*[0-9]+ \(nt; pentium\)/
	| /ibm-proxy-wte\/([0-9]+\.)*[0-9]+/
	| /netscape-commerce\/[0-9]+\.[0-9]+/
	| /nde/
	;

function do_apache_server(server: string): string
	{
	local apache_parts = split_all(server, apache_server);
	if ( apache_parts[3] == "" )
		return apache_parts[2];

	local apache_return_string = apache_parts[2];
	local mod_parts = split(apache_parts[3], / /);

	for ( part in mod_parts )
		{
		if ( mod_parts[part] == apache_mod_pat )
			{
			apache_return_string =
				string_cat(apache_return_string,
					" ");
			apache_return_string =
				string_cat(apache_return_string,
					mod_parts[part]);
			}
		else
			print http_anon_log, fmt("** unknown Apache mod: %s:%s", mod_parts[part], server);
		}

	return apache_return_string;
	}

function check_server(server: string, server_pat: pattern): bool
	{
	return server_pat in server;
	}

function do_server(server: string, server_pat: pattern): string
	{
	return split_all(server, server_pat)[2];
	}

function filter_in_http_server(server: string): string
	{
	# Vanilla Apache is a hard one and a special case.  Let's get the
	# nastiness over first.

	if ( apache_server in server )
		return do_apache_server(server);

	if ( check_server(server, apache_misc) )
		return do_server(server, apache_misc);
	if ( check_server(server, IBM_server) )
		return do_server(server, IBM_server);
	if ( check_server(server, zedo_server) )
		return do_server(server, zedo_server);
	if ( check_server(server, zope_server) )
		return do_server(server, zope_server);
	if ( check_server(server, jetty_server) )
		return do_server(server, jetty_server);
	if ( check_server(server, thttp_server) )
		return do_server(server, thttp_server);
	if ( check_server(server, weblogic_server) )
		return do_server(server, weblogic_server);

	# Grab bag.
	if ( misc_server in server )
		return server;

	# Best guess - unknown Apache variant of some sort.
	if ( apache_basic in server )
		{
		print http_anon_log,
			fmt("** unknown Apache variant: %s", server);

		return fmt("(bro: unknown) %s %s",
				split_all(server, apache_basic)[2],
				split_all(server, apache_platforms)[2]);
		}

	print http_anon_log, fmt("** unknown server: %s", server);

	return fmt("(bro: unknown) %s", anonymize_arg("server", server));
	}
