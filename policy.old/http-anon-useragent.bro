# $Id:$

# Filter-in known "USER-AGENT:" values.

@load anon
@load http-anon-utils

# ---------------------------------------------------------------------
#                      Mozilla (and friends)
# ---------------------------------------------------------------------

const mozilla_full_pat =
	/mozilla\/[0-9]\.[0-9] \(( *|;|iebar| freebsd i[0-9]{1,4}|fr|-|windows|windows 98|sunos sun4u|compatible|msie [0-9]\.[0-9]|windows nt [0-9]\.[0-9]|google-tr-1|sv1|\.net clr ([0-9]\.)*[0-9]+|x11|en|ppc mac os x|macintosh|u|linux i[0-9]{1,4}|en-us|rv\:([0-9]+\.)*[0-9]+|aol [0-9]\.[0-9]|gnotify ([0-9]+\.)*[0-9]+)*\) *(gecko\/[0-9]+)? *(firefox\/([0-9]+.)*[0-9]+)?/;

const mozilla_head_pat = /mozilla\/[0-9]\.[0-9]/;

const misc_user_pat =
	  /spiderman/
	| /w3m\/([0-9]+\.)*[0-9]+/
	| /java([0-9]+\.)*[0-9]+(_[0-9]+)?/
	| /java\/([0-9]+\.)*[0-9]+(_[0-9]+)?/
	| /freecorder/
	| /industry update control/
	| /microsoft-cryptoapi\/([0-9]+\.)*[0-9]+/
	| /ruriko\/([0-9]+\.)*[0-9]+/
	| /crawler[0-9]\.[0-9]/
	| /w3search/
	| /symantec liveupdate/
	| /davkit\/[0-9]\.[0-9]/
	| /windows-media-player\/([0-9]+\.)*[0-9]+/
	| /winamp\/([0-9]+\.)*[0-9]+/
	| /headdump/
	;

const misc_cmplx_user_pat =
	  /lynx\/([0-9]+\.)*[0-9]+.*/
	| /wget\/([0-9]+\.)*[0-9]+.*/
	| /yahooseeker\/([0-9]+\.)*[0-9]+.*/
	| /rma\/([0-9]+\.)*[0-9]+.*/
	| /aim\/[0-9]+.*/
	| /ichiro\/([0-9]+\.)*[0-9]+.*/
	| /unchaos.*/
	| /irlbot\/[0-9]\.[0-9]+.*/
	| /msnbot\/([0-9]+\.)*[0-9]+.*/
	| /opera\/([0-9]+\.)*[0-9]+.*/
	| /netnewswire\/([0-9]+\.)*[0-9]+.*/
	| /nsplayer\/([0-9]+\.)*[0-9]+.*/
	| /aipbot\/([0-9]+\.)*[0-9]+.*/
	| /mac os x; webservicescore\.framework.*/
	| /fast-webcrawler\/([0-9]+\.)*[0-9]+.*/
	| /skype.*/
	| /googlebot\/([0-9]+\.)*[0-9]+.*/
	;

const misc_cmplx_user_start =
	  /lynx\/([0-9]+\.)*[0-9]+/
	| /wget\/([0-9]+\.)*[0-9]+/
	| /yahooseeker\/([0-9]+\.)*[0-9]+/
	| /rma\/([0-9]+\.)*[0-9]+/
	| /aim\/[0-9]+/
	| /ichiro\/([0-9]+\.)*[0-9]+/
	| /unchaos/
	| /irlbot\/[0-9]\.[0-9]+/
	| /opera\/([0-9]+\.)*[0-9]+/
	| /msnbot\/([0-9]+\.)*[0-9]+/
	| /netnewswire\/([0-9]+\.)*[0-9]+/
	| /nsplayer\/([0-9]+\.)*[0-9]+/
	| /aipbot\/([0-9]+\.)*[0-9]+/
	| /mac os x; webservicescore\.framework/
	| /fast-webcrawler\/([0-9]+\.)*[0-9]+/
	| /skype/
	| /googlebot\/([0-9]+\.)*[0-9]+/
	;

function filter_in_http_useragent(user: string): string
	{
	# Check for an exact match for Mozilla.
	if ( mozilla_full_pat in user )
		return split_all(user, mozilla_full_pat)[2];

	# Look for popular Mozilla-compatible crawlers.
	if ( mozilla_head_pat in user )
		{
		local crawler = "(bro: unknown)";

		if ( /.*yahoo\! slurp/ in user )
			crawler = "(yahoo! slurp)";

		else if ( /.*ask jeeves/ in user )
			crawler = "(ask jeeves)";

		else
			print http_anon_log,
				fmt("*** unknown Mozilla user-agent %s\n", user);

		return fmt("%s %s", split_all(user, mozilla_head_pat)[2],
				crawler);
		}

	# Some simple, common user names.
	if ( misc_user_pat in user )
		return user;

	# Require some info removal.
	if ( misc_cmplx_user_pat in user )
		return split_all(user, misc_cmplx_user_pat)[2];

	print http_anon_log,fmt("*** unknown user agent %s\n", user);

	return fmt("(bro: unknown) %s", anonymize_arg("user-agent", user));
	}
