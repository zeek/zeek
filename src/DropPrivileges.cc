// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "DropPrivileges.h"

#include <initializer_list>

#ifdef __linux__
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>

static void BindRemount(const char *path, unsigned long flags) noexcept
	{
	if (mount(path, path, nullptr, MS_BIND, nullptr) == 0)
		mount(nullptr, path, nullptr, MS_REMOUNT|MS_BIND|flags,
		      nullptr);
	}

static void HardenFilesystems() noexcept
	{
	/* create a new mount namespace, so the following mounts
	   affect only this process and nobody else */
	if (unshare(CLONE_NEWNS) < 0)
		return;

	/* convert all "shared" mounts to "private" mounts */
	if (mount(nullptr, "/", nullptr, MS_PRIVATE|MS_REC, nullptr) < 0)
		return;

	/* we don't need those filesystems */
	for (const char *path : {"/proc", "/sys", "/dev/pts", "/dev/hugepages", "/dev/mqueue", "/run"})
		umount2(path, MNT_DETACH);

	/* mount a private tmpfs here so we're not affected by
	   other processes */
	for (const char *path : {"/tmp", "/var/tmp", "/dev/shm"})
		mount("none", path, "tmpfs",
		      MS_NODEV|MS_NOEXEC|MS_NOSUID,
		      "size=16M,nr_inodes=256,mode=1777");

	/* remount those paths read-only so we can't do any
	   harm here */
	BindRemount("/usr", MS_RDONLY|MS_NODEV|MS_NOSUID);
	BindRemount("/opt", MS_RDONLY|MS_NODEV|MS_NOSUID);
	BindRemount("/etc", MS_RDONLY|MS_NODEV|MS_NOEXEC);
	}

#endif

void DropPrivileges() noexcept
	{
#ifdef __linux__
	HardenFilesystems();

#ifdef PR_SET_NO_NEW_PRIVS
	/* shut off all ways to regain privileges (suid bits etc.) */
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
#endif

	/* this drops all capabilities and effectively makes this
	   process unprivileged (even though it's still "root" and
	   still has access to "root"-owned processes and files), but
	   this currently fails with errno=EINVAL because the allows
	   this only if there are no threads yet - to make this work,
	   we must change our initalization order and move libcaf
	   initialization to after this call */
	unshare(CLONE_NEWUSER);

	/* this would isolate our process from the rest, but this
	   breaks thread creation (need to figure out how to do this
	   properly) */
	//unshare(CLONE_NEWPID);
#endif
	}
