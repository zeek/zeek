# @TEST-DOC: Smoke the policy/protocols/ftp scripts don't fall apart.
# @TEST-EXEC: zeek -b -r $TRACES/ftp/ipv6-multiline-reply.trace %INPUT
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: btest-diff .stderr

@load protocols/ftp/detect
@load protocols/ftp/detect-bruteforcing
