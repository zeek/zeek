signature webapp-wordpress {
	http-reply-body /.*(<link rel=(\"|')stylesheet(\"|') [^>]+wp-content|<meta name=(\"|')generator(\"|') [^>]+WordPress[^\"]+)/
	event "WordPress"
}

signature webapp-xoops {
	http-reply-body /.*<meta name=(\"|')generator(\"|') [^>]+XOOPS/
	event "Xoops"
}

signature webapp-phpmyadmin {
	http-reply-body /.*(var pma_absolute_uri = '|PMA_sendHeaderLocation\(|<title>phpMyAdmin<\/title>)/
	event "phpMyAdmin"
}

signature webapp-phppgadmin {
	http-reply-body /.*(<title>phpPgAdmin<\/title>|<span class=(\"|')appname(\"|')>phpPgAdmin)/
	event "phpPgAdmin"
}

signature webapp-phpbb {
	http-reply-body /.*(Powered by (<a href=(\"|')[^>]+)?phpBB|<meta name=(\"|')copyright(\"|') [^>]+phpBB Group)/
	event "phpBB"
}

signature webapp-joomla {
	http-reply-body /.*(<meta name=(\"|')generator(\"|') [^>]+Joomla|<!\-\- JoomlaWorks \"K2\")/
	http-reply-header /X-Content-Encoded-By: Joomla/
	event "Joomla"
}

signature webapp-google-analytics {
	http-reply-body /.*(\.google\-analytics\.com\/ga\.js|<script src=(\"|')[^\"]+google\-analytics\.com\/urchin\.js(\"|'))/
	event "Google Analytics"
}

signature webapp-cpanel {
	http-reply-body /.*<!-- cPanel/
	event "cPanel"
}

signature webapp-mediawiki {
	http-reply-body /.*(<meta name=(\"|')generator(\"|') [^>]+MediaWiki|<a[^>]+>Powered by MediaWiki<\/a>)/
	event "MediaWiki"
}

signature webapp-moodle {
	http-reply-body /.*(var moodleConfigFn = function\(me\)|<img[^>]+moodlelogo)/
	event "Moodle"
}

signature webapp-oscommerce {
	http-reply-body /.*<!-- header_eof \/\/-->/
	event "osCommerce"
}

signature webapp-plesk {
	http-reply-body /.*<script[^>]* src=(\"|')[^>]*common\.js\?plesk/
	event "Plesk"
}

signature webapp-plone {
	http-reply-body /.*<meta name=(\"|')generator(\"|') [^>]+Plone/
	event "Plone"
}

signature webapp-redmine {
	http-reply-body /.*(<meta name=(\"|')description(\"|')Redmine(\"|')|Powered by <a href=(\"|')[^>]+Redmine)/
	event "Redmine"
}

signature webapp-trac {
	http-reply-body /.*(<a id=(\"|')tracpowered)/
	event "Trac"
}

signature webapp-typo3 {
	http-reply-body /.*(<meta name=(\"|')generator(\"|') [^>]+TYPO3|<(script[^>]* src|link[^>]* href)=[^>]*fileadmin)/
	event "Typo3"
}

signature webapp-drupal {
	http-reply-body /.*(<script [^>]+drupal\.js|jQuery\.extend\(Drupal\.settings, \{|Drupal\.extend\(\{ settings: \{|<link[^>]+sites\/(default|all)\/themes\/|<style[^>]+sites\/(default|all)\/(themes|modules)\/)/
	event "Drupal"
}