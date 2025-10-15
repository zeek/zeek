# List of HTTP headers pulled from:
#   https://www.iana.org/assignments/http-methods/http-methods.xhtml
#   https://learn.microsoft.com/en-us/previous-versions/office/developer/exchange-server-2003/aa142917(v=exchg.65)
#   https://datatracker.ietf.org/doc/html/rfc3253 (MKWORKSPACE)
#   Microsoft's RPC over HTTP protocol (RPC_IN_DATA / RPC_OUT_DATA)
#
# The headers in the signature below are ordered by the list of sources
# above, with the exception of putting some of the more commonly-
# encountered methods earlier in the regex.
#
# We match each side of the connection independently to avoid missing
# large HTTP sessions where one side exceeds the DPD buffer size on
# its own already. See https://github.com/zeek/zeek/issues/343.

signature dpd_http_client {
  ip-proto == tcp
  payload /^[[:space:]]*(OPTIONS|GET|HEAD|POST|PUT|DELETE|ACL|BASELINE-CONTROL|BIND|CHECKIN|CHECKOUT|CONNECT|COPY|LABEL|LINK|LOCK|MERGE|MKACTIVITY|MKCALENDAR|MKCOL|MKREDIRECTREF|MOVE|ORDERPATCH|PATCH|PROPFIND|PROPPATCH|REBIND|REPORT|SEARCH|TRACE|UNBIND|UNCHECKOUT|UNLINK|UNLOCK|UPDATE|VERSION-CONTROL|BCOPY|BDELETE|BMOVE|BPROPFIND|BPROPPATCH|NOTIFY|POLL|SUBSCRIBE|UNSUBSCRIBE|X-MS-ENUMATTS|MKWORKSPACE|RPC_IN_DATA|RPC_OUT_DATA)[[:space:]]*/
  tcp-state originator
  enable "http"
}

signature dpd_http_server {
  ip-proto == tcp
  payload /^[hH][tT][tT][pP]\/[0-9]/
  tcp-state responder
  enable "http"
}
