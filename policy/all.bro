##! This script only aims at loading all of the base analysis scripts.

@load conn
@load dns
@load ftp
@load http
@load irc
@load mime 
@load smtp
@load ssh
@load ssl
@load syslog

#@load communication
@load metrics
@load notice
@load signatures
@load software

@load detectors/http-MHR

@load tuning/defaults