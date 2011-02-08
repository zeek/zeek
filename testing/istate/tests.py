# $Id: tests.py,v 1.1.2.5 2005/10/11 22:31:42 sommer Exp $
#
# Various helper functions.

import sys
import os
import copy
import errno
import signal
import subprocess

# Path to our files.
Testing = os.path.abspath(".")

# Path to top-level Bro directory.
if os.path.exists("../../build"):
    BroBuild = os.path.abspath("../../build")
    BroPath = subprocess.Popen(["/bin/sh", "-c", "../../build/bro-path-dev"], stdout=subprocess.PIPE).communicate()[0]
else:
    print >>sys.stderr, "cannot find build directory"
    sys.exit(1)

# Path where tmp files are created.
Tmp = os.path.join(Testing, "tmp")

# Path to seed file.
BroSeed = os.path.join(Testing, "rndseed.dat")

# Path to our test scripts.
Scripts = os.path.join(Testing, "scripts")

# Path to our test traces.
Traces = os.path.join(Testing, "traces")

# Where the base files to compare against are stored.
Base = os.path.join(os.getcwd(), "./base")

# Process ID of all processes we've spawned, indexed by textual tag *and* pid.
Running = {}

# Set to true when at least one check failed.
Failed = False

# getopt options
Options = None

def error(str):
    print >>sys.stderr, "Error:", str
    sys.exit(1)

def debug(str):
    if Options.debug:
        print >>sys.stderr, "Debug:", str

def log(str):
    print >>sys.stderr, str

# Returns full path of given process' working directory.
def workDir(tag):
    return os.path.join(Tmp, tag)

# Intializes work dir for given process.
def initWorkDir(tag):

    try:
        os.mkdir(Tmp)
    except OSError, e:
        if e.errno != errno.EEXIST:
            raise

    os.system("rm -rf " + workDir(tag))
    os.mkdir(workDir(tag))

# Spawns process identified by the given tag. Enters process into RunningBro.
def spawnProc(tag, cmdline, copy=[]):
    initWorkDir(tag)
    os.chdir(workDir(tag))

    for i in copy:
        debug("Copying %s into workdir of %s" % (i, tag))
        os.system("cp -r %s %s" % (i, workDir(tag)))

    debug("Spawning '%s' as %s" % (" ".join(cmdline), tag))

    saved_stdin = os.dup(0)
    saved_stdout = os.dup(1)
    saved_stderr = os.dup(2)
    child_stdin = open("/dev/null", "r")
    child_stdout = open("stdout.log", "w")
    child_stderr = open("stderr.log", "w")
    os.dup2(child_stdin.fileno(), 0)
    os.dup2(child_stdout.fileno(), 1)
    os.dup2(child_stderr.fileno(), 2)
    pid = os.spawnvp(os.P_NOWAIT, cmdline[0], cmdline)
    os.dup2(saved_stdin, 0)
    os.dup2(saved_stdout, 1)
    os.dup2(saved_stderr, 2)

    Running[tag] = pid
    Running[pid] = tag

# Spaws a Bro process.
def spawnBro(tag, args, copy=[]):
    os.putenv("BROPATH", BroPath + ":" + Scripts)
    os.unsetenv("BRO_LOG_SUFFIX")
    args += ["--load-seeds", BroSeed, "-B", "state,comm"]
    spawnProc(tag, [os.path.join(BroBuild, "src/bro")] + args, copy=copy)

# Examines a process' exit code.
def parseExitCode(tag, result):
    if os.WCOREDUMP(result):
        error("process %s core dumped." % tag)

    if os.WIFSIGNALED(result):
        error("process %s got signal %d." % (tag, os.WTERMSIG(result)))

    if not os.WIFEXITED(result):
        error("process %s exited abnormally (%d)." % (tag, result))

    result = os.WEXITSTATUS(result)
    debug("process %s exited with %d" % (tag, result))

    return result

# Waits for process to finish.
def waitProc(tag):
    (pid, result) = os.waitpid(Running[tag], 0)
    result = parseExitCode(tag, result)
    if result != 0:
	error("Execution of %s failed." % tag)

    del Running[pid]
    del Running[tag]

# Waits for all of our processes to terminte.
def waitProcs():
    while Running:
        (pid, result) = os.waitpid(0, 0)
        parseExitCode(Running[pid], result)
        del Running[Running[pid]]
        del Running[pid]

# Kills the process and waits for its termination.
def killProc(tag):
    pid = Running[tag]
    debug("Killing %s..." % tag)
    os.kill(pid, signal.SIGTERM)
    (pid, result) = os.waitpid(pid, 0)
    parseExitCode(tag, result)
    del Running[pid]
    del Running[tag]

# Cleans up temporary stuff
def cleanup():
    os.system("rm -rf " + Tmp)

# Canonicalizes file content for diffing.
def canonicalizeFile(file, ignoreTime, ignoreSessionID, sort, delete):

    cmd = []

    if delete:
        for i in delete:
            cmd += ["sed 's/%s//g' | grep -v '^$'" % i]

    if ignoreTime:
        cmd += ["sed 's/[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]\.[0-9][0-9]\{0,6\}/xxxxxxxxxx.xxxxxx/g'"]

    if ignoreSessionID:
        # A session is either "%1" or "%my-peer-description-1"
        cmd += ["sed 's/%\([^ ]*-\)\{0,1\}[0-9][0-9]*/%XXX/g'"]

    if sort:
        cmd += ["LC_ALL=c sort"]

    if not cmd:
        return

    tmp = file + ".tmp"
    cmd = "cat %s | %s >%s" % (file, " | ".join(cmd), tmp)

    debug("Canonicalizing '%s'" % cmd)
    os.system(cmd)
    os.system("mv %s %s" % (tmp, file))

# Diffs the two files, If mismatch, prints "FAILED" and returns true.
def diff(file1, file2):

    quiet = ">/dev/null"
    if Options.showdiff:
        quiet = ""

    for f in (file1, file2):
        if not os.path.exists(f):
            print "FAILED (%s does not exist)" % f
            return False

    diff = "diff -u %s %s %s" % (file1, file2, quiet)

    debug("Executing '%s'" % diff)
    result = os.system(diff)

    if os.WEXITSTATUS(result) != 0:
        print "FAILED"
        return False

    return True

# Compares files of process against base version. Returns false if mismatch found.
def checkFiles(tag, files, ignoreTime, sort, delete):
    base = os.path.join(Base, tag)
    work = workDir(tag)

    print "    Checking %s..." % tag,

    failed = False

    for file in files:
        oldfile = os.path.join(base, file)
        newfile = os.path.join(work, file)

        canonicalizeFile(newfile, ignoreTime, False, sort, delete)

        if not diff(oldfile, newfile):
            failed = True
            break

    if not failed:
        print "ok"
    else:
        Failed = failed

# Compares files of two processes. Return false if mismatch found.
def compareFiles(tag1, tag2, files, ignoreTime=False, ignoreSessionID=False, sort=False, delete=None):
    work1 = workDir(tag1)
    work2 = workDir(tag2)

    print "    Comparing %s with %s..." % (tag1, tag2),

    failed = False

    for file in files:
        file1 = os.path.join(work1, file)
        file2 = os.path.join(work2, file)

        canonicalizeFile(file1, ignoreTime, ignoreSessionID, sort, delete)
        canonicalizeFile(file2, ignoreTime, ignoreSessionID, sort, delete)

        if not diff(file1, file2):
            failed = True
            break

    if not failed:
        print "ok"
    else:
        Failed = failed

# Make the result of process new baseline.
def makeNewBase(tag, files, ignoreTime, sort, delete):

    try:
        os.mkdir(Base)
    except OSError, e:
        if e.errno != errno.EEXIST:
            raise

    base = os.path.join(Base, tag)
    work = workDir(tag)

    print "    Copying files for %s..." % tag

    try:
        os.mkdir(base)
    except OSError, e:
        if e.errno != errno.EEXIST:
            raise

    # Delete all files but those belonging to CVS.
    os.system("find %s -type f -not -path '*/CVS/*' -not -path '*/.svn/*' -exec rm '{}' ';'" % base)

    for file in files:
        oldfile = os.path.join(work, file)
        newfile = os.path.join(base, file)
	os.system("cp %s %s" % (oldfile, newfile))
        canonicalizeFile(newfile, ignoreTime, False, sort, delete)

def testSet(set):
    if Options.set and set != Options.set:
        return False

    print "Running set '%s' ..." % set
    return True

# Either check given files or make it new baseline, depending on options.
def finishTest(tag, files, ignoreTime=False, sort=False, delete=None):
    if Options.newbase:
	makeNewBase(tag, files, ignoreTime, sort, delete)
    else:
	checkFiles(tag, files, ignoreTime, sort, delete)
