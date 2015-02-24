# @TEST-EXEC: bro -r $TRACES/radius/radius.trace %INPUT
# @TEST-EXEC: btest-diff auth.log

@load policy/frameworks/auth/radius-dhcp
