# @TEST-EXEC: bro -r $TRACES/radius/radius2.trace %INPUT
# @TEST-EXEC: btest-diff auth.log

@load policy/frameworks/auth/radius-dhcp
