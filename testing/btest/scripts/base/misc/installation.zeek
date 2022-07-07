# This test verifies that the directories in base/misc/installation.zeek do get
# substituted to absolute paths. It does not verify the path strings themselves
# since they may change from build to build.

# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/utils/paths
@load base/misc/installation

global dirs = vector(Installation::root_dir, Installation::etc_dir,
    Installation::log_dir, Installation::spool_dir, Installation::state_dir);

for ( i in dirs )
	{
	if ( dirs[i] != absolute_path_pat )
		print dirs[i];
	}
