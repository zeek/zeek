# $Id: execute.py 6956 2009-12-14 22:01:17Z robin $
#
# These modules provides a set of functions to execute actions on a host.
# If the host is local, it's done direcly; if it's remote we log in via SSH. 

import os
import sys
import socket
import shutil
import re
import util
import time
import subprocess

import config

haveBroccoli = True

try:
    import broccoli
except ImportError:
    haveBroccoli = False

LocalAddrs = None 

# Wrapper around subprocess.POpen()
def popen(cmdline, stderr_to_stdout=False):
    stderr = None
    if stderr_to_stdout:
        stderr = subprocess.STDOUT

    # os.setid makes sure that the child process doesn't receive our CTRL-Cs.
    proc = subprocess.Popen([cmdline], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, 
                            close_fds=True, shell=True, preexec_fn=os.setsid)
    # Compatibility with older popen4.
    proc.tochild = proc.stdin
    proc.fromchild = proc.stdout

    return proc

# Returns true if given node corresponds to the host we're running on.
def isLocal(node):
    global LocalAddrs 
    if not LocalAddrs:
        (success, output) = runLocalCmd(os.path.join(config.Config.scriptsdir, "local-interfaces"))
        if not success:
            if not config.Config.installing():
                util.warn("cannot get list of local IP addresses")

            try:
                # This does not work for multi-homed hosts.
                LocalAddrs = [socket.gethostbyname(socket.gethostname()), "127.0.0.1"]
            except:
                LocalAddrs = ["127.0.0.1"]
        else:
            LocalAddrs = [line.strip() for line in output]

        util.debug(1, "Local IPs: %s" % ",".join(LocalAddrs))

    return not node or node.host == "localhost" or node.addr in LocalAddrs

# Takes list of (node, dir) pairs and ensures the directories exist on the nodes' host.
# Returns list of (node, sucess) pairs.
def mkdirs(dirs):

    results = []
    cmds = []
    fullcmds = []

    for (node, dir) in dirs:
        # We make local directories directly. 
        if isLocal(node):
            if not exists(node, dir):
                util.debug(1, "%-10s %s" % ("[local]", "mkdir %s" % dir))
                os.mkdir(dir)

            results += [(node, True)]

        else:
            cmds += [(node, [], [])]
                # Need to be careful here as our helper scripts may not be installed yet. 
            fullcmds += [("test -d %s || mkdir %s 2>/dev/null; echo $?; echo ~~~" % (dir, dir))]

    for (node, success, output) in runHelperParallel(cmds, fullcmds=fullcmds):
        results += [(node, success)]

    return results

# Takes list of (node, dir) pairs and ensures the directories exist on the nodes' host.
# Returns list of (node, sucess) pairs.
def mkdir(node, dir):
    return mkdirs([(node, dir)])[0][1]

def rmdirs(dirs):
    results = []
    cmds = []

    for (node, dir) in dirs:
        # We remove local directories directly. 
        if isLocal(node):
            (success, output) = captureCmd("rm -rf %s" % dir)
            results += [(node, success)]
        else:
            cmds += [(node, "rmdir", [dir])]

    for (node, success, output) in runHelperParallel(cmds):
        results += [(node, success)]

    return results

# Removes the directory on the host if it's there.
def rmdir(node, dir):
    return rmdirs([(node, dir)])[0][1]

# Returns true if the path exists on the host.
def exists(host, path):
    if isLocal(host):
        return os.path.lexists(path)
    else:
        (success, output) = runHelper(host, "exists", [path])
        return success

# Returns true if the path exists and refers to a file on the host.
def isfile(host, path):
    if isLocal(host):
        return os.path.isfile(path)
    else:
        util.error("isfile() not yet supported for remote hosts")

# Returns true if the path exists and refers to a directory on the host.
def isdir(host, path):
    if isLocal(host):
        return os.path.isdir(path)
    else:
        (success, output) = runHelper(host, "is-dir", [path])
        return success

# Copies src to dst, preserving permission bits.
# Works for files and directories (non-recursive).
def install(host, src, dst):
    if isLocal(host):
        if not exists(host, src):
            util.output("file does not exist: %s" % src)
            return False

        if os.path.isfile(dst):
            os.remove(dst)

        util.debug(1, "cp %s %s" % (src, dst))
        shutil.copy2(src, dst)
        return True
    else:
        util.error("install() not yet supported for remote hosts")
        return False

# rsyns paths from localhost to destination hosts. 
def sync(nodes, paths):

    cmds = []
    for n in nodes:
        args = ["-a", "--delete", "--rsh=\"ssh -o ConnectTimeout=30\""]
        dst = ["%s:%s/" % (n.host, config.Config.brobase)]
        args += paths + dst
        cmdline = "rsync %s" % " ".join(args)
        cmds += [(n, cmdline, "", None)]

    for (id, success, output) in runLocalCmdsParallel(cmds):
        if not success:
            util.warn("error rsyncing to %s: %s" % (id.host, output))

# Checks whether the given host is alive.    
_deadHosts = {}

def isAlive(host):

    if host in _deadHosts:
        return False

    (success, output) = runLocalCmd(os.path.join(config.Config.scriptsdir, "is-alive") + " " + host)

    if not success and not config.Config.cron == "1":
        _deadHosts[host] = True
        util.warn("host %s is not alive" % host)

    return success

# Runs command locally and returns tuple (success, output)
# with success being true if the command terminated with exit code 0, 
# and output being the combinded stdout/stderr output of the command. 
def captureCmd(cmd, env = "", input = None):

    cmdline = env + " " + cmd
    util.debug(1, "%-10s %s" % ("[local]", cmdline))

    proc = popen(cmdline, stderr_to_stdout=True)

    if input:
        print >>proc.tochild, input
        proc.tochild.close()

    rc = proc.wait()
    output = [line.strip() for line in proc.fromchild]

    util.debug(1, "%-10s exit code %d" % ("[local]", os.WEXITSTATUS(rc)))
    for line in output:
        util.debug(2, "           > %s" % line)

    return (os.WIFEXITED(rc) and os.WEXITSTATUS(rc) == 0, output)

## FIXME: Replace "captureCmd" with "runLocalCmd".

# Runs command locally and returns tuple (success, output)
# with success being true if the command terminated with exit code 0, 
# and output being the combinded stdout/stderr output of the command. 
def runLocalCmd(cmd, env = "", input=None):
    proc = _runLocalCmdInit("single", cmd, env, input)
    if not proc:
        return (False, [])

    return _runLocalCmdWait(proc)

# Same as above but runs a set of local commands in parallel.
# Cmds is a list of (id, cmd, envs, input) tuples, where id is 
# an arbitrary cookie identifying each command.
# Returns a list of (id, success, output) tuples.
# 'output' is None (vs. []) if we couldn't connect to host.
def runLocalCmdsParallel(cmds):

    results = []
    running = []

    for (id, cmd, envs, input) in cmds:
        proc = _runLocalCmdInit(id, cmd, envs, input)
        if proc:
            running += [(id, proc)]
        else:
            results += [(id, False, None)]

    for (id, proc) in running:
        status  = _runLocalCmdWait(proc)
        if status:
            (success, output) = status
            results += [(id, success, output)]
        else:
            results += [(id, False, None)]

    return results

def _runLocalCmdInit(id, cmd, env, input):

    if not env:
        env = ""

    cmdline = env + " " + cmd
    util.debug(1, "%-10s %s" % ("[local]", cmdline))

    proc = popen(cmdline, stderr_to_stdout=True)

    if input:
        print >>proc.tochild, input

    proc.tochild.close()
    return proc

def stripNL(str):
    if len(str) == 0 or str[-1] != "\n":
        return str

    return str[0:-1]

def _runLocalCmdWait(proc):

    rc = proc.wait()
    output = [stripNL(line) for line in proc.fromchild]

    util.debug(1, "%-10s exit code %d" % ("[local]", os.WEXITSTATUS(rc)))
    for line in output:
        util.debug(2, "           > %s" % line)

    return (os.WIFEXITED(rc) and os.WEXITSTATUS(rc) == 0, output)

# Runs a helper script from bin/helpers, according to the helper
# protocol. 
# If fullcmd is given, this is the exact & complete command line (incl. paths). 
# Otherwise, cmd is just the helper's name (wo/ path) and args are the 
# arguments. Env is an optional enviroment variable of the form
# "key=val". Return value as for captureCmd().
# 'output' is None (vs. []) if we couldn't connect to host.
def runHelper(host, cmd=None, args=None, fullcmd=None, env = ""):
    util.disableSignals()
    try:
        status = _runHelperInit(host, cmd, args, fullcmd, env)
        if not status:
            return (False, None)

        status = _runHelperWait(status)
        if not status:
            return (False, None)

        return status

    finally:
        util.enableSignals()

# Same as above but runs commands on a set of hosts in parallel.
# Cmds is a list of (node, cmd, args) tuples.
# Fullcmds, if given, is a parallel list of full command lines. 
# Envs, if given, is a parallel list of env variables.
# Returns a list of (node, success, output) tuples.
# 'output' is None (vs. []) if we couldn't connect to host.
def runHelperParallel(cmds, fullcmds = None, envs = None):

    util.disableSignals()

    try:
        results = []
        running = []

        for (node, cmd, args) in cmds:

            if fullcmds:
                fullcmd = fullcmds[0]
                fullcmds = fullcmds[1:]
            else:
                fullcmd = ""

            if envs:
                env = envs[0]
                envs = envs[1:]
            else:
                env = ""

            status = _runHelperInit(node, cmd, args, fullcmd, env)
            if status:
                running += [node]
            else:
                results += [(node, False, None)]

        for node in running:
            status =  _runHelperWait(node)
            if status:
                (success, output) = status
                results += [(node, success, output)]
            else:
                results += [(node, False, None)]

        return results

    finally:
        util.enableSignals()

# Helpers for running helpers. 
#
# We keep the SSH sessions open across calls to runHelper.
Connections = {}
WhoAmI = None

# FIXME: This is an ugly hack. The __del__ method produces
# strange unhandled exceptions in the child at termination
# of the main process. Not sure if disabling the cleanup
# altogether is a good thing but right now that's the 
# only fix I can come up with.
def _emptyDel(self):
    pass
subprocess.Popen.__del__ = _emptyDel

def _getConnection(host):

    global WhoAmI
    if not WhoAmI:
        (success, output) = captureCmd("whoami")
        if not success:
            util.error("can't get 'whoami'")
        WhoAmI = output[0]

    if not host:
        host = config.Config.manager()

    if host.tag in Connections:
        p = Connections[host.tag]
        if p.poll() != None:
            # Terminated.
            global _deadHosts
            _deadHosts[host.host] = True
            util.warn("connection to %s broke" % host.host)
            return None

        return (p.stdin, p.stdout)

    if isLocal(host):
        cmdline = "sh"
    else:
        # Check whether host is alive. 
        if not isAlive(host.host):
            return None

        cmdline = "ssh -o ConnectTimeout=30 -l %s %s sh" % (WhoAmI, host.host)

    util.debug(1, "%-10s %s" % ("[local]", cmdline))

    try:
        p = popen(cmdline)
    except OSError, e:
        util.warn("cannot login into %s [IOError: %s]" % (host.host, e))
        return None

    Connections[host.tag] = p
    return (p.stdin, p.stdout)

def _runHelperInit(host, cmd, args, fullcmd, env):

    c = _getConnection(host)
    if not c:
        return None

    (stdin, stdout) = c

    if not fullcmd:
        cmdline = "%s %s %s" % (env, os.path.join(config.Config.helperdir, cmd), " ".join(args))
    else:
        cmdline = fullcmd

    util.debug(1, "%-10s %s" % (("[%s]" % host.host), cmdline))
    print >>stdin, cmdline
    stdin.flush()

    return host

def _runHelperWait(host):
    output = []
    while True:

        c = _getConnection(host)
        if not c:
            return None

        (stdin, stdout) = c

        line = stdout.readline().strip()
        if line == "~~~":
            break
        output += [line]

    try:
        rc = int(output[0])
    except ValueError:
        util.warn("cannot parse exit code from helper on %s: %s" % (host.host, output[0]))
        rc = 1

    util.debug(1, "%-10s exit code %d" % (("[%s]" % host.host), rc))

    for line in output:
        util.debug(2, "           > %s" % line)

    return (rc == 0, output[1:])

# Broccoli communication with running nodes.

# Sends event  to a set of nodes in parallel.
#
# events is a list of tuples of the form (node, event, args, result_event).
#   node:    the destination node.
#   event:   the name of the event to send (node that receiver must subscribe to it as well).
#   args:    a list of event args; each arg must be a data type understood by the Broccoli module.
#   result_event: name of a event the node sends back. None if no event is sent back.
#
# Returns a list of tuples (node, success, results_args).
#   If success is True, result_args is a list of arguments as shipped with the result event, 
#   or [] if no result_event was specified.
#   If success is False, results_args is a string with an error message.

def sendEventsParallel(events):

    results = []
    sent = []

    for (node, event, args, result_event) in events:

        if not haveBroccoli:
            results += [(node, False, "no Python bindings for Broccoli installed")]
            continue

        (success, bc) = _sendEventInit(node, event, args, result_event)
        if success and result_event:
            sent += [(node, result_event, bc)]
        else:
            results += [(node, success, bc)]

    for (node, result_event, bc) in sent:
        (success, result_args) = _sendEventWait(node, result_event, bc)
        results += [(node, success, result_args)]

    return results

def _sendEventInit(node, event, args, result_event):

    try:
        bc = broccoli.Connection("%s:%d" % (node.addr, node.getPort()), broclass="update", 
                                 flags=broccoli.BRO_CFLAG_ALWAYS_QUEUE, connect=False)
        bc.subscribe(result_event, _event_callback(bc))
        bc.got_result = False
        bc.connect()
    except IOError, e:
        util.debug(1, "%-10s broccoli: cannot connect" % (("[%s]" % node.tag)))
        return (False, str(e))

    util.debug(1, "%-10s broccoli: %s(%s)" % (("[%s]" % node.tag), event, ", ".join(args)))
    bc.send(event, *args)
    return (True, bc)

def _sendEventWait(node, result_event, bc):
    # Wait until we have sent the event out. 
    cnt = 0
    while bc.processInput():
        time.sleep(1)

        cnt += 1
        if cnt > 10:
            util.debug(1, "%-10s broccoli: timeout during send" % (("[%s]" % node.tag)))
            return (False, "time-out")

    if not result_event:
        return (True, [])

    # Wait for reply event.
    cnt = 0
    bc.processInput();
    while not bc.got_result:
        time.sleep(1)
        bc.processInput();

        cnt += 1
        if cnt > 10:
            util.debug(1, "%-10s broccoli: timeout during receive" % (("[%s]" % node.tag)))
            return (False, "time-out")

    util.debug(1, "%-10s broccoli: %s(%s)" % (("[%s]" % node.tag), result_event, ", ".join(bc.result_args)))
    return (True, bc.result_args)

def _event_callback(bc):
    def save_results(*args):
        bc.got_result = True
        bc.result_args = args
    return save_results

