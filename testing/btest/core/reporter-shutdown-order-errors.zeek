# @TEST-EXEC: touch reporter.log && chmod -w reporter.log
# @TEST-EXEC: zeek %INPUT >out 2>&1

# Output doesn't really matter, but we just want to know that Bro shutdowns
# without crashing in such scenarios (reporter log not writable
# and also reporter errors being emitting during shutdown).

redef Config::config_files += { "./config" };

