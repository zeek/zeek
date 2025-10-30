signature http-reply-body-matcher {
	http-reply-body /.*<body>/
	event "Found reply!"
}

signature http-reply-body-matcher2 {
	http-reply-body /.*301 Moved Permanently/
	event "Found reply!"
}
