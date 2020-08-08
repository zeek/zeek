#
# @TEST-EXEC: zeek -b -C -r $TRACES/www-odd-url.trace base/protocols/http
# @TEST-EXEC: btest-diff http.log

