# @TEST-EXEC: touch reporter.log && chmod -w reporter.log
# @TEST-EXEC: bro %INPUT >out 2>&1
# @TEST-EXEC: btest-diff out

redef Config::config_files += { "./config" };

