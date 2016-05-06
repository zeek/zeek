signature dpd_xmpp {
	ip-proto == tcp
	payload /^(<\?xml[^?>]*\?>)?[\n\r ]*<stream:stream [^>]*xmlns='jabber:/
	enable "xmpp"
}
