# List of HTTP headers pulled from:
#   http://annevankesteren.nl/2007/10/http-methods
#
# We match each side of the connection independently to avoid missing
# large HTTP sessions where one side exceeds the DPD buffer size on
# its own already. See https://github.com/zeek/zeek/issues/343.

signature dpd_http_client {
  ip-proto == tcp
  payload /^[[:space:]]*(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH|BCOPY|BDELETE|BMOVE|BPROPFIND|BPROPPATCH|NOTIFY|POLL|SUBSCRIBE|UNSUBSCRIBE|X-MS-ENUMATTS|RPC_OUT_DATA|RPC_IN_DATA)[[:space:]]*/
  tcp-state originator
  enable "http"
}

signature dpd_http_server {
  ip-proto == tcp
  payload /^HTTP\/[0-9]/
  tcp-state responder
  enable "http"
}
