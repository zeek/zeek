# @TEST-EXEC: bro misc/loaded-scripts
# @TEST-EXEC: wc -l < loaded_scripts.log | awk '$1 > 1 { print "Some scripts were loaded" }' > output
# @TEST-EXEC: btest-diff output
