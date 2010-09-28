#! /usr/bin/env python
#
# $Id: control.py 6948 2009-12-03 20:59:41Z robin $
#
# Functions to control the nodes' operations.

import os
import sys
import glob
import fileinput
import time
import tempfile
import re

import execute
import util
import config
import cron
import install

# Convert a number into a string with a unit (e.g., 1024 into "1M").
def prettyPrintVal(val):
    for (prefix, unit, factor) in (("", "G", 1024*1024*1024), ("", "M", 1024*1024), ("", "K", 1024), (" ", "", 0)):
        if val >= factor:
            return "%s%3.0f%s" % (prefix, val / factor, unit)
    return val # Should not happen

# Checks multiple nodes in parallel and returns list of tuples (node, isrunning). 
def isRunning(nodes, setcrashed=True):

    results = []
    cmds = []

    for node in nodes:
        pid = node.getPID()
        if not pid:
            results += [(node, False)]
            continue

        cmds += [(node, "check-pid", [pid])]

    for (node, success, output) in execute.runHelperParallel(cmds):

        # If we cannot connect to the host at all, we filter it out because
        # the process might actually still be running but we can't tell.
        if output == None:
            util.warn("cannot connect to %s" % node.tag)
            continue

        results += [(node, success)]

        if not success:
            if setcrashed:
                # Grmpf. It crashed. 
                node.clearPID();
                node.setCrashed()

    return results

# Waits for the nodes' Bro processes to reach the given status. 
def waitForBros(nodes, status, timeout, ensurerunning):

    # If ensurerunning is true, process must still be running.
    if ensurerunning:
        running = isRunning(nodes)
    else:
        running = [(node, True) for node in nodes]

    results = []

    # Determine set of nodes still to check.
    todo = {}
    for (node, isrunning) in running:
        if isrunning:
            todo[node.tag] = node 
        else:
            results += [(node, False)]

    points = False
    while True:

        # Determine  whether process is still running. We need to do this
        # before we get the state to avoid a race condition.
        running = isRunning(todo.values(), setcrashed=False)

        # Check nodes' .status file
        cmds = []
        for node in todo.values():
            cmds += [(node, "cat-file", ["%s/.status" % node.cwd()])]

        for (node, success, output) in execute.runHelperParallel(cmds):
            if success:
                try:
                    (stat, loc) = output[0].split()
                    if status in stat:
                        # Status reached. Cool.
                        del todo[node.tag]
                        results += [(node, True)]
                except IndexError:
                    # Something's wrong. We give up on that node.
                    del todo[node.tag]
                    results += [(node, False)]

        for (node, isrunning) in running:
            if node.tag in todo and not isrunning:
                # Alright, a dead node's status will not change anymore.
                del todo[node.tag]
                results += [(node, False)]

        if len(todo) == 0:
            # All done.
            break

        # Wait a bit before we start over.
        time.sleep(1)

        # Timeout reached?
        timeout -= 1
        if timeout <= 0:
            break

        util.output("%d " % len(todo), nl=False)
        points = True

    for node in todo.values():
        # These did time-out.
        results += [(node, False)]

    if points:
        util.output("%d " % len(todo))

    return results

# Build the Bro parameters for the given node. Include
# script for live operation if live is true.
def _makeBroParams(node, live):
    args = []

    if live:
        try:
            args += ["-i %s " % node.interface]
        except AttributeError:
            pass

        if config.Config.savetraces == "1":
            args += ["-w trace.pcap"]

        args += ["-U .status"]

    args += ["-p broctl"]

    if node.type != "standalone":
        args += ["-p cluster"]
    else:
        args += ["-p standalone"]

    for p in config.Config.prefixes.split(":"):
        args += ["-p %s" % p]

    args += ["-p %s" % node.tag]         
        
    args += node.scripts

    if live:
        args += ["broctl-live"]
    else:
        args += ["broctl-check"]

    if node.type == "worker" or node.type == "proxy":
        args += config.Config.sitepolicyworker.split()
        args += config.Config.auxscriptsworker.split()

    if node.type == "manager":
        args += config.Config.sitepolicymanager.split()
        args += config.Config.auxscriptsmanager.split()

    if node.type == "standalone":
        args += config.Config.sitepolicystandalone.split()
        args += config.Config.auxscriptsstandalone.split()

    if "aux_scripts" in node.__dict__:
        args += [node.aux_scripts]

    args += ["analysis-policy"]

    if config.Config.broargs:
        args += [config.Config.broargs]

#   args += ["-B comm,serial"]

    return args

# Build the environment variable for the given node. 
def _makeEnvParam(node):
    env = ""
    env = "BRO_%s=%s" % (node.type.upper(), str(node.count))

    return env

# Do a "post-terminate crash" for the given nodes.
def _makeCrashReports(nodes):
    cmds = []
    for node in nodes:
        cmds += [(node, "run-cmd",  [os.path.join(config.Config.scriptsdir, "post-terminate"), node.cwd(),  "crash"])]

    for (node, success, output) in execute.runHelperParallel(cmds):
        if not success:
            util.output("cannot run post-terminate for %s" % node.tag)
        else:
            util.sendMail("Crash report from %s" % node.tag, "\n".join(output))

        node.clearCrashed()

# Starts the given nodes. Returns true if all nodes were successfully started.
def _startNodes(nodes):

    result = True

    filtered = []
    # Ignore nodes which are still running.
    for (node, isrunning) in isRunning(nodes):
        if not isrunning: 
            filtered += [node]
            util.output("starting %s ..." % node.tag)
        else:
            util.output("%s still running" % node.tag)

    nodes = filtered

    # Generate crash report for any crashed nodes.
    crashed = [node for node in nodes if node.hasCrashed()]
    _makeCrashReports(crashed)

    # Make working directories.
    dirs = [(node, node.cwd()) for node in nodes]
    nodes = []
    for (node, success) in execute.mkdirs(dirs):
        if success:
            nodes += [node]
        else:
            util.output("cannot create working directory for %s" % node.tag)
            result = False

    # Start Bro process.
    cmds = []
    envs = []
    for node in nodes:
        cmds += [(node, "start", [node.cwd()] + _makeBroParams(node, True))]
        envs += [_makeEnvParam(node)]

    nodes = []
    for (node, success, output) in execute.runHelperParallel(cmds, envs=envs):
        if success:
            nodes += [node]
            node.setPID(int(output[0]))
        else:
            util.output("cannot start %s" % node.tag)
            result = False

    # Check whether processes did indeed start up.
    hanging = []
    running = []

    for (node, success) in waitForBros(nodes, "RUNNING", 3, True):
        if success:
            running += [node]
        else:
            hanging += [node]

    # It can happen that Bro hangs in DNS lookups at startup
    # which can take a while. At this point we already know
    # that the process has been started (waitForBro ensures that). 
    # If by now there is not a TERMINATED status, we assume that it
    # is doing fine and will move on to RUNNING once DNS is done.
    for (node, success) in waitForBros(hanging, "TERMINATED", 0, False):
        if success:
            util.output("%s terminated immediately after starting; check output with \"diag\"" % node.tag)
            node.clearPID()
            result = False
        else:
            util.output("(%s still initializing)" % node.tag)
            running += [node]

    for node in running:
        cron.logAction(node, "started")

    return result

# Start Bro processes on nodes if not already running.
def start(nodes):

    if len(nodes) > 0:
        # User picked nodes to start.
        _startNodes(nodes)
        return

    # Start all nodes. Do it in the order manager, proxies, workers. 
    if not _startNodes(config.Config.nodes("manager")):
        return

    if not _startNodes(config.Config.nodes("proxies")):
        return

    if not _startNodes(config.Config.nodes("workers")):
        return

def _stopNodes(nodes):

    running = []

    # Check for crashed nodes. 
    for (node, isrunning) in isRunning(nodes):
        if isrunning: 
            running += [node]
            util.output("stopping %s ..." % node.tag)
        else:
            if node.hasCrashed():
                _makeCrashReports([node])
                util.output("%s not running (was crashed)" % node.tag)
            else:
                util.output("%s not running" % node.tag)

    # Helper function to stop nodes with given signal. 
    def stop(nodes, signal):
        cmds = []
        for node in nodes:
            cmds += [(node, "stop", [node.getPID(), str(signal)])] 

        return execute.runHelperParallel(cmds)

    # Stop nodes.
    for (node, success, output) in stop(running, 15):
        if not success:
            util.output("failed to send stop signal to %s" % node.tag)

    if running:
        time.sleep(1)

    # Check whether they terminated.
    terminated = []
    kill = []
    for (node, success) in waitForBros(running, "TERMINATED", 60, False):
        if not success:
            # Check whether it crashed during shutdown ...
            result = isRunning([node])
            for (node, isrunning) in result:
                if isrunning:
                    util.output("%s did not terminate ... killing ..." % node.tag)
                    kill += [node]
                else:
                    # crashed flag is set by isRunning().
                    util.output("%s crashed during shutdown" % node.tag)

    if len(kill):
        # Kill those which did not terminate gracefully.
        stop(kill, 9)
        # Given them a bit to disappear.
        time.sleep(5) 

    # Check which are still running. We check all nodes to be on the safe side
    # and give them a bit more time to finally disappear.
    timeout = 10

    todo = {}
    for node in running:
        todo[node.tag] = node

    while True:

        running = isRunning(todo.values(), setcrashed=False)

        for (node, isrunning) in running:
            if node.tag in todo and not isrunning:
                # Alright, it's gone. 
                del todo[node.tag]
                terminated += [node]

        if len(todo) == 0:
            # All done.
            break

        # Wait a bit before we start over.

        if timeout <= 0:
            break

        time.sleep(1)
        timeout -= 1

    # Do post-terminate cleanup for those which terminated gracefully.
    cleanup = [node for node in terminated if not node.hasCrashed()]

    cmds = []
    for node in cleanup:
        cmds += [(node, "run-cmd",  [os.path.join(config.Config.scriptsdir, "post-terminate"), node.cwd()])] 

    for (node, success, output) in execute.runHelperParallel(cmds):
        if not success:
            util.output("cannot run post-terminate for %s" % node.tag)
            cron.logAction(node, "stopped (failed)")
        else:
            cron.logAction(node, "stopped")

        node.clearPID()
        node.clearCrashed()

# Stop Bro processes on nodes.
def stop(nodes):

    if len(nodes) > 0:
        # User picked nodes to stop.
        _stopNodes(nodes)
        return

    # Start all nodes. Do it in the order workers, proxies, manager. 
    _stopNodes(config.Config.nodes("workers"))
    _stopNodes(config.Config.nodes("proxies"))
    _stopNodes(config.Config.nodes("manager"))

# First stop, then start Bro processes on nodes. 
def restart(nodes, clean):

    if len(nodes) > 0:
        all_nodes = nodes
    else:
        all_nodes = config.Config.nodes()

    util.output("stopping ...")
    if len(nodes) > 0:
        # User picked nodes to restart.
        _stopNodes(nodes)
    else:
        stop([])

    if clean:
        # Can't delete the tmp here because log archival might still be going on there in the background.
        cleanup(all_nodes, False)

        util.output("checking configuration ...")
        if not checkConfigs(all_nodes):
            return 

        util.output("installing ...")
        install.install(False, False)

    util.output("starting ...")
    if len(nodes) > 0:
        _startNodes(nodes)
    else:
        start([])

# Output status summary for nodes. 
def status(nodes):

    util.output("%-10s %-10s %-10s %-13s %-6s %-6s %-20s " % ("Name",  "Type", "Host", "Status", "Pid", "Peers", "Started"))

    all = isRunning(nodes)
    running = []

    cmds1 = []
    cmds2 = []
    for (node, isrunning) in all:
        if isrunning:
            running += [node]
            cmds1 += [(node, "cat-file", ["%s/.startup" % node.cwd()])]
            cmds2 += [(node, "cat-file", ["%s/.status" % node.cwd()])]

    startups = execute.runHelperParallel(cmds1)
    statuses = execute.runHelperParallel(cmds2)

    startups = dict([(n.tag, success and util.fmttime(output[0]) or "???") for (n, success, output) in startups])
    statuses = dict([(n.tag, success and output[0].split()[0].lower() or "???") for (n, success, output) in statuses])

    peers = {}
    nodes = [n for n in running if statuses[n.tag] == "running"]
    for (node, success, args) in _queryPeerStatus(nodes):
        if success:
            peers[node.tag] = []
            for f in args[0].split():
                (key, val) = f.split("=")
                if key == "peer" and val != "":
                    peers[node.tag] += [val]
        else:
            peers[node.tag] = None

    for (node, isrunning) in all:

        util.output("%-10s " % node.tag, nl=False)
        util.output("%-10s %-10s " % (node.type, node.host), nl=False)

        if isrunning:
            util.output("%-13s " % statuses[node.tag], nl=False)

        elif node.hasCrashed():
            util.output("%-13s " % "crashed", nl=False)
        else:
            util.output("%-13s " % "stopped", nl=False)

        if isrunning:
            util.output("%-6s " % node.getPID(), nl=False)

            if node.tag in peers and peers[node.tag] != None:
                util.output("%-6d " % len(peers[node.tag]), nl=False)
            else: 
                util.output("%-6s " % "???", nl=False)

            util.output("%-8s  " % startups[node.tag], nl=False)

        util.output()

# Outputs state of remote connections for host.     


# Helper for getting top output.
#
# Returns tuples of the form (node, error, vals) where  'error' is None if we 
# were able to get the data or otherwise a string with an  error message; 
# in case there's no error, 'vals' is a list of dicts which map tags to their values.
#
# Tags are "pid", "proc", "vsize", "rss", "cpu", and "cmd".
#
# We do all the stuff in parallel across all nodes which is why this looks 
# a bit confusing ...
def getTopOutput(nodes):

    results = []
    cmds = []

    running = isRunning(nodes)

    # Get all the PIDs first.

    pids = {}
    parents = {}

    for (node, isrunning) in running:
        if isrunning:
            pid = node.getPID()
            pids[node.tag] = [int(pid)]
            parents[node.tag] = pid

            cmds += [(node, "get-childs", [pid])]
        else:
            results += [(node, "not running", [{}])]
            continue

    if not cmds:
        return results

    for (node, success, output) in execute.runHelperParallel(cmds):

        if not success:
            results += [(node, "cannot get child pids", [{}])]
            continue

        pids[node.tag] += [int(line) for line in output]

    cmds = []

    # Now run top.
    for node in nodes: # Do the loop again to keep the order.
        if not node.tag in pids:
            continue

        cmds += [(node, "top", [])]

    if not cmds:
        return results

    for (node, success, output) in execute.runHelperParallel(cmds):

        if not success:
            results += [(node, "cannot get top output", [{}])]

        procs = [line.split() for line in output if int(line.split()[0]) in pids[node.tag]]

        if not procs:
            # It can happen that on the meantime the process is not there anymore.
            results += [(node, "not running", [{}])]
            continue

        vals = []

        for p in procs:
            d = {}
            d["pid"] = int(p[0])
            d["proc"] = (p[0] == parents[node.tag] and "parent" or "child") 
            d["vsize"] = int(p[1])
            d["rss"] = int(p[2])
            d["cpu"] = p[3]
            d["cmd"] = " ".join(p[4:])
            vals += [d]

        results += [(node, None, vals)]

    return results

# Produce a top-like output for node's processes.
# If hdr is true, output column headers first. 
def top(nodes):

    util.output("%-10s %-10s %-10s %-8s %-8s %-8s %-8s %-8s %-8s" % ("Name", "Type", "Node", "Pid", "Proc", "VSize", "Rss", "Cpu", "Cmd"))

    for (node, error, vals) in getTopOutput(nodes):

        if not error:
            for d in vals:
                util.output("%-10s " % node.tag, nl=False)
                util.output("%-10s " % node.type, nl=False)
                util.output("%-10s " % node.host, nl=False)
                util.output("%-8s " % d["pid"], nl=False)
                util.output("%-8s " % d["proc"], nl=False)
                util.output("%-8s " % prettyPrintVal(d["vsize"]), nl=False)
                util.output("%-8s " % prettyPrintVal(d["rss"]), nl=False)
                util.output("%-8s " % ("%s%%" % d["cpu"]), nl=False)
                util.output("%-8s " % d["cmd"], nl=False)
                util.output()
        else:
            util.output("%-10s " % node.tag, nl=False)
            util.output("%-8s " % node.type, nl=False)
            util.output("%-8s " % node.host, nl=False)
            util.output("<%s> " % error, nl=False)
            util.output()

def _doCheckConfig(nodes, installed, list_scripts, fullpaths):

    ok = True

    manager = config.Config.manager()

    all = [(node, os.path.join(config.Config.tmpdir, "check-config-%s" % node.tag)) for node in nodes]

    nodes = []
    for (node, cwd) in all:
        if os.path.isdir(cwd):
            if not execute.rmdir(config.Config.manager(), cwd):
                util.output("cannot remove directory %s on manager" % cwd)
                continue

        if not execute.mkdir(config.Config.manager(), cwd):
            util.output("cannot create directory %s on manager" % cwd)
            continue

        nodes += [(node, cwd)]

    cmds = []
    for (node, cwd) in nodes:

        env = ""
        if node.type == "worker" or node.type == "proxy":
            env = "BRO_%s=%s" % (node.type.upper(), str(node.count))

        dashl = list_scripts and ["-l"] or []

        broargs =  " ".join(dashl + _makeBroParams(node, False)) + " terminate"
        installed_policies = installed and "1" or "0"

        cmd = os.path.join(config.Config.scriptsdir, "check-config") + " %s %s %s" % (installed_policies, cwd, broargs)

        cmds += [((node, cwd), cmd, env, None)]

    for ((node, cwd), success, output) in execute.runLocalCmdsParallel(cmds):

        if not list_scripts:

            if success:
                util.output("%s is ok." % node.tag)
            else:
                ok = False
                util.output("%s failed." % node.tag)
                for line in output:
                    util.output("   %s" % line)

        else:
            util.output(node.tag)
            for line in output:
                if line.find("loading") >= 0:

                    line = line.replace("loading ", "")
                    if not fullpaths:
                        line = re.sub("\S+/", "", line)

                    util.output("   %s" % line)

            if not success:
                ok = False
                util.output("%s failed to load all scripts correctly." % node.tag)

        execute.rmdir(manager, cwd)

    return ok

# Check the configuration for nodes without installing first.
def checkConfigs(nodes):
    return _doCheckConfig(nodes, False, False, False)

# Extracts the list of loaded scripts from the -l output. 
def listScripts(nodes, paths, check):
    _doCheckConfig(nodes, not check, True, paths)

# Report diagostics for node (e.g., stderr output).
def crashDiag(node):

    util.output("[%s]" % node.tag)

    if not execute.isdir(node, node.cwd()):
        util.output("No work dir found\n")
        return

    (rc, output) = execute.runHelper(node, "run-cmd",  [os.path.join(config.Config.scriptsdir, "crash-diag"), node.cwd()])
    if not rc:
        util.output("cannot run crash-diag for %s" % node.tag)
        return

    for line in output:
        util.output(line)

# Clean up the working directory for nodes (flushes state). 
# If cleantmp is true, also wipes ${tmpdir}; this is done
# even when the node is still running.
def cleanup(nodes, cleantmp=False):
    util.output("cleaning up nodes ...")
    result = isRunning(nodes)
    running =    [node for (node, on) in result if on]
    notrunning = [node for (node, on) in result if not on]

    execute.rmdirs([(n, n.cwd()) for n in notrunning])
    execute.mkdirs([(n, n.cwd()) for n in notrunning])

    for node in notrunning:
        node.clearCrashed();

    for node in running:
        util.output("   %s is still running, not cleaning work directory" % node.tag)

    if cleantmp:
        execute.rmdirs([(n, config.Config.tmpdir) for n in running + notrunning])
        execute.mkdirs([(n, config.Config.tmpdir) for n in running + notrunning])

# Attach gdb to the main Bro processes on the given nodes.    
def attachGdb(nodes):
    running = isRunning(nodes)

    cmds = []
    for (node, isrunning) in running:
        if isrunning:
            cmds += [(node, "gdb-attach", ["gdb-%s" % node.tag, config.Config.bro, node.getPID()])]

    results = execute.runHelperParallel(cmds)
    for (node, success, output) in results:
        if success:
            util.output("gdb attached on %s" % node.tag)
        else:
            util.output("cannot attach gdb on %s: %s" % node.tag, output)

# Helper for getting capstats output.
#
# Returns tuples of the form (node, error, vals) where  'error' is None if we 
# were able to get the data or otherwise a string with an error message; 
# in case there's no error, 'vals' maps tags to their values.
#
# Tags are those as returned by capstats on the command-line
#
# We do all the stuff in parallel across all nodes which is why this looks 
# a bit confusing ...

# Gather capstats from interfaces.
def getCapstatsOutput(nodes, interval):

    if not config.Config.capstats:
        if config.Config.cron == "0":
            util.warn("do not have capstats binary available")
        return []

    results = []
    cmds = []

    hosts = {}
    for node in nodes:
        try:
            hosts[(node.addr, node.interface)] = node
        except AttributeError:
            continue

    for (addr, interface) in hosts.keys():
        node = hosts[addr, interface]

        capstats = [config.Config.capstats, "-i", interface, "-I", str(interval), "-n", "1"]

# Unfinished feature: only consider a particular MAC. Works here for capstats
# but Bro config is not adapted currently so we disable it for now. 
#        try:
#            capstats += ["-f", "\\'", "ether dst %s" % node.ether, "\\'"]
#        except AttributeError:
#            pass

        cmds += [(node, "run-cmd", capstats)]

    outputs = execute.runHelperParallel(cmds) 

    for (node, success, output) in outputs:

        if not success:
            results += [(node, "%s: cannot execute capstats" % node.tag, {})]
            continue

        fields = output[0].split()
        vals = { }

        try:
            for field in fields[1:]:
                (key, val) = field.split("=")
                vals[key] = float(val)

            results += [(node, None, vals)]

        except ValueError:
            results += [(node, "%s: unexpected capstats output: %s" % (node.tag, output[0]), {})]

    return results

# Get current statistics from cFlow. 
#
# Returns dict of the form port->(cum-pkts, cum-bytes). 
#
# Returns None if we can't run the helper sucessfully.
def getCFlowStatus():
    (success, output) = execute.runLocalCmd(os.path.join(config.Config.scriptsdir, "cflow-stats"))
    if not success or not output:
        util.warn("failed to run cflow-stats")
        return None

    vals = {}

    for line in output:
        try:
            (port, pps, bps, pkts, bytes) = line.split()
            vals[port] = (float(pkts), float(bytes))
        except ValueError:
            # Probably an error message because we can't connect. 
            util.warn("failed to get cFlow statistics: %s" % line)
            return None

    return vals

# Calculates the differences between to getCFlowStatus() calls. 
# Returns tuples in the same form as getCapstatsOutput() does.
def calculateCFlowRate(start, stop, interval):
    diffs = [(port, stop[port][0] - start[port][0], (stop[port][1] - start[port][1])) for port in start.keys() if port in stop]

    rates = []
    for (port, pkts, bytes) in diffs:
        vals = { "kpps": "%.1f" % (pkts / 1e3 / interval) }
        if start[port][1] >= 0:
            vals["mbps"] = "%.1f" % (bytes * 8 / 1e6 / interval)

        rates += [(port, None, vals)]

    return rates

def capstats(nodes, interval):

    def output(tag, data):
        util.output("\n%-12s %-10s %-10s (%ds average)" % (tag, "kpps", "mbps", interval))
        util.output("-" * 30)

        for (port, error, vals) in data:

            if error:
                util.output(error)
                continue

            util.output("%-12s " % port, nl=False)

            if not error:
                util.output("%-10s " % vals["kpps"], nl=False)
                if "mbps" in vals:
                    util.output("%-10s " % vals["mbps"], nl=False)
                util.output()
            else:
                util.output("<%s> " % error)

    have_cflow = config.Config.cflowaddress and config.Config.cflowuser and config.Config.cflowpassword
    have_capstats = config.Config.capstats

    if not have_cflow and not have_capstats:
        util.warn("do not have capstats binary available")
        return

    if have_cflow:
        cflow_start = getCFlowStatus()

    if have_capstats:
        capstats = [(node.tag, error, vals) for (node, error, vals) in getCapstatsOutput(nodes, interval)]

    else:
        time.sleep(interval)

    if have_cflow:
        cflow_stop = getCFlowStatus()

    if have_capstats:    
        output("Interface", sorted(capstats))

    if have_cflow and cflow_start and cflow_stop:
        diffs = calculateCFlowRate(cflow_start, cflow_stop, interval)
        output("cFlow Port", sorted(diffs))

# Update the configuration of a running instance on the fly.     
def update(nodes):

    running = isRunning(nodes)

    cmds = []
    for (node, isrunning) in running:
        if isrunning:
            env = _makeEnvParam(node)
            env += " BRO_DNS_FAKE=1"
            args = " ".join(_makeBroParams(node, False))
            cmds += [(node.tag, os.path.join(config.Config.scriptsdir, "update") + " %s %s" % (node.tag.replace("worker-", "w"), args), env, None)]
            util.output("updating %s ..." % node.tag)

    results = execute.runLocalCmdsParallel(cmds)

    for (tag, success, output) in results:
        if not success:
            util.output("could not update %s: %s" % (tag, output))
        else:
            util.output("%s: %s" % (tag, output[0]))

# Enable/disable types of analysis.
def toggleAnalysis(types, enable=True):

    ana = config.Config.analysis()

    for t in types:
        if ana.isValid(t.lower()):
            ana.toggle(t.lower(), enable)
        else:
            util.output("unknown analysis type '%s'" % t)


# Print summary of analysis status.
def showAnalysis():
    for (tag, status, mechanism, descr) in config.Config.analysis().all():
        print "%15s is %s  -  %s" % (tag, (status and "enabled " or "disabled"), descr)

# Gets disk space on all volumes relevant to broctl installation.
# Returns dict which for each node has a list of tuples (fs, total, used, avail).
def getDf(nodes):

    dirs = ("logdir", "bindir", "helperdir", "cfgdir", "spooldir", "policydir", "libdir", "tmpdir", "staticdir", "scriptsdir")

    df = {}
    for node in nodes:
        df[node.tag] = {}

    for dir in dirs:
        path = config.Config.config[dir]

        cmds = []
        for node in nodes:
            cmds += [(node, "df", [path])]

        results = execute.runHelperParallel(cmds)

        for (node, success, output) in results:
            if success:
                fields = output[0].split()

                # Ignore NFS mounted volumes.
                if fields[0].find(":") < 0:
                    df[node.tag][fields[0]] = fields


    result = {}
    for node in df:
        result[node] = df[node].values()

    return result 

def df(nodes):

    util.output("%10s  %15s  %-5s  %-5s  %-5s" % ("", "", "total", "avail", "capacity"))

    for (node, dfs) in getDf(nodes).items():
        for df in dfs:
            total = float(df[1])
            used = float(df[2])
            avail = float(df[3])
            perc = used * 100.0 / (used + avail)

            util.output("%10s  %15s  %-5s  %-5s  %-5.1f%%" % (node, df[0], 
                prettyPrintVal(total), 
                prettyPrintVal(avail), perc))


def printID(nodes, id):
    running = isRunning(nodes)

    events = []
    for (node, isrunning) in running:
        if isrunning:
            events += [(node, "request_id", [id], "request_id_response")]

    results = execute.sendEventsParallel(events)

    for (node, success, args) in results:
        if success:
            print "%10s   %s = %s" % (node.tag, args[0], args[1])
        else:
            print "%10s   <error: %s>" % (node.tag, args)

def _queryPeerStatus(nodes):
    running = isRunning(nodes)

    events = []
    for (node, isrunning) in running:
        if isrunning:
            events += [(node, "get_peer_status", [], "get_peer_status_response")]

    return execute.sendEventsParallel(events)

def _queryNetStats(nodes):
    running = isRunning(nodes)

    events = []
    for (node, isrunning) in running:
        if isrunning:
            events += [(node, "get_net_stats", [], "get_net_stats_response")]

    return execute.sendEventsParallel(events)

def peerStatus(nodes):
    for (node, success, args) in _queryPeerStatus(nodes):
        if success:
            print "%10s\n%s" % (node.tag, args[0])
        else:
            print "%10s   <error: %s>" % (node.tag, args)

def netStats(nodes):
    for (node, success, args) in _queryNetStats(nodes):
        if success:
            print "%10s: %s" % (node.tag, args[0]),
        else:
            print "%10s: <error: %s>" % (node.tag, args)

def executeCmd(nodes, cmd):

    for special in "|'\"":
        cmd = cmd.replace(special, "\\" + special)

    cmds = [(n, "run-cmd", [cmd]) for n in nodes]

    for (node, success, output) in execute.runHelperParallel(cmds):
      util.output("[%s] %s\n> %s" % (node.host, (success and " " or "error"), "\n> ".join(output)))



