# @TEST-EXEC: zeek -b -U status-file -e ''
# @TEST-EXEC: btest-diff status-file

# @TEST-EXEC: zeek -b -U /cannot/write/to/this/file -e '' 2>&1 | sed 's/: [0-9]\{1,\}/: XX/g' | sed "s|'[^']*cannot/write/to/this/file'|'/cannot/write/to/this/file'|g" | sort | uniq >error
# @TEST-EXEC: btest-diff error
