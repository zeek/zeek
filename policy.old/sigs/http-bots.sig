# $Id:$
#
# Some signatures for detecting certain HTTP-based botnet activity.

signature nethell {
	http-request /.*php\?userid=/
	http-request-body /userid=[0-9]{8}_/
	event "Nethell request"
}

signature bzub {
	http-request /.*ver=.*&lg=.*&phid=.*&r=/
	http-request-body /phid=[A-F0-9]{64}/
	event "bzub request"
}

signature iebho {
	http-request /.*ver=.*&lg=.*&phid=/
	http-request-body /phid=[A-F0-9]{32}/
	event "IEBHO request"
}

signature bebloh {
	payload /^GET/
	http-request /.*get\.php\?type=slg&id=/
	event "Bebloh request"
}

signature black_enery {
	payload /^POST/
	http-request-header /Cache-Control: no-cache/
	http-request-body /.*id=.*&build_id=.*id=x.+_[0-9A-F]{8}&build_id=.+/
	event "Black energy request"
}

signature waledec {
	payload /^POST/
	http-request /\/[A-Za-z0-9]+\.[pP][nN][gG]/
	event "Waledec request"
}

signature silentbanker {
	payload /^POST/
	http-request /.*\/getcfg\.php/
	event "SilentBanker request"
}

signature icepack {
	payload /^GET/
	http-request /.*\/exe\.php/
	event "Icepack request"
}

signature torpig {
	payload /^POST/
	http-request /.*\/gate\.php/
	event "Torpig request"
}

signature peed {
	http-request /.*\/controller\.php\?action=/
	http-request /.*&entity/
	http-request /.*&rnd=/
	event "Peed request"
}

signature gozi {
	payload /^GET/
	http-request /.*\?user_id=/
	http-request /.*&version_id=/
	http-request /.*&crc=/
	event "Gozi request"
}

signature wsnpoem {
	payload /^GET/
	http-request /.*\/((cfg|config)[0-9]*)\.bin$/
	event "wsnpoem request"
}

signature pinch {
	payload /^POST/
	http-request /.*\?act=online&.*s4=.*&s5=.*&nickname=/
	http-request-body /.*msg_out=/
	event "pinch request"
}

signature grum {
	payload /^GET/
	http-request /.*s_alive\.php/
	event "Grum request"
}

