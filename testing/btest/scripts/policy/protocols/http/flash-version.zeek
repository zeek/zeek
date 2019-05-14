# @TEST-EXEC: zeek -r ${TRACES}/http/flash-version.trace %INPUT 
# @TEST-EXEC: btest-diff software.log

@load protocols/http/software
@load protocols/http/software-browser-plugins

redef Software::asset_tracking = ALL_HOSTS;

