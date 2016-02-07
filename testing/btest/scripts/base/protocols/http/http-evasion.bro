# @TEST-EXEC: bro -Cr $TRACES/http/http-evasion.trace %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log

