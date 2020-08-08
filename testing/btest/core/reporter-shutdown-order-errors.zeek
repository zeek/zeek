# @TEST-EXEC: touch reporter.log && chmod -w reporter.log
# @TEST-EXEC: zeek -b %INPUT >out 2>&1

# Output doesn't really matter, but we just want to know that Zeek shutdowns
# without crashing in such scenarios (reporter log not writable
# and also reporter errors being emitting during shutdown).

@load base/frameworks/config

redef Config::config_files += { "./config" };

