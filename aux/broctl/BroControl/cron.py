#! /usr/bin/env python
#
# $Id: cron.py 6813 2009-07-07 18:54:12Z robin $
#
# Tasks which are to be done on a regular basis from cron.

import os
import sys

import util
import config
import execute
import control
import time
import shutil

# Triggers all activity which is to be done regularly via cron.
def doCron():

    if config.Config.cronenabled == "0":
        return

    if not util.lock():
        return

    util.bufferOutput()
    config.Config.config["cron"] = "1"  # Flag to indicate that we're running from cron.

    # Check whether nodes are still running an restart if neccessary.
    for (node, isrunning) in control.isRunning(config.Config.nodes()):
        if not isrunning and node.hasCrashed():
            control.start([node])

    # Check for dead hosts.
    _checkHosts()

    # Generate statistics. 
    _logStats(5)

    # Check available disk space.
    _checkDiskSpace()

    # Expire old log files.
    _expireLogs()

    # Update the HTTP stats directory. 
    _updateHTTPStats()

    # Run external command if we have one.
    if config.Config.croncmd:
        execute.runLocalCmd(config.Config.croncmd)

    # Mail potential output.
    output = util.getBufferedOutput()
    if output:
        util.sendMail("cron: " + output.split("\n")[0], output)

    config.Config.config["cron"] = "0"

    util.unlock()

def logAction(node, action):
    t = time.time()
    out = open(config.Config.statslog, "a")
    print >>out, t, node.tag, "action", action
    out.close()

def _logStats(interval):

    nodes = config.Config.nodes()
    top = control.getTopOutput(nodes)

    have_cflow = config.Config.cflowaddress and config.Config.cflowuser and config.Config.cflowpassword
    have_capstats = config.Config.capstats
    cflow_start = cflow_end = None
    capstats = []
    cflow_rates = []

    if have_cflow:
        cflow_start = control.getCFlowStatus()

    if have_capstats:
        capstats = control.getCapstatsOutput(nodes, interval)
    elif have_cflow:
        time.sleep(interval)

    if have_cflow:
        cflow_end = control.getCFlowStatus()
        if cflow_start and cflow_end:
            cflow_rates = control.calculateCFlowRate(cflow_start, cflow_end, interval)

    t = time.time()

    out = open(config.Config.statslog, "a")

    for (node, error, vals) in top:
        if not error:
            for proc in vals:
                type = proc["proc"]
                for (val, key) in proc.items():
                    if val != "proc":
                        print >>out, t, node.tag, type, val, key
        else:
            print >>out, t, node.tag, "error", "error", error

    for (node, error, vals) in capstats:
        if not error:
            for (key, val) in vals.items():
                # Report if we don't see packets on an interface.
                tag = "lastpkts-%s" % node.tag

                if key == "pkts":
                    if tag in config.Config.state:
                        last = float(config.Config.state[tag])
                    else:
                        last = -1.0

                    if float(val) == 0.0 and last != 0.0:
                        util.output("%s is not seeing any packets on interface %s" % (node.host, node.interface))

                    if float(val) != 0.0 and last == 0.0:
                        util.output("%s is seeing packets again on interface %s" % (node.host, node.interface))

                    config.Config._setState(tag, val)

                print >>out, t, node.tag, "interface", key, val

        else:
            print >>out, t, node.tag, "error", "error", error

    for (port, error, vals) in cflow_rates:
        if not error:
            for (key, val) in vals.items():
                print >>out, t, "cflow", port.lower(), key, val

    out.close()

def _checkDiskSpace():

    minspace = float(config.Config.mindiskspace)
    if minspace == 0.0:
        return

    for (node, dfs) in control.getDf(config.Config.nodes()).items():
        for df in dfs:
            fs = df[0]
            total = float(df[1])
            used = float(df[2])
            avail = float(df[3])
            perc = used * 100.0 / (used + avail)
            key = "disk-space-%s%s" % (node, fs.replace("/", "-"))

            if perc > 100 - minspace:
                try:
                    if float(config.Config.state[key]) > 100 - minspace:
                        # Already reported.
                        continue
                except KeyError:
                    pass

                util.output("Disk space low on %s:%s - %.1f%% used." % (node, fs, perc))

            config.Config.state[key] = "%.1f" % perc

def _expireLogs():

    i = int(config.Config.logexpireinterval)

    if not i:
        return

    (success, output) = execute.runLocalCmd(os.path.join(config.Config.scriptsdir, "expire-logs"))

    if not success:
        util.output("error running expire-logs\n\n")
        util.output(output)

def _checkHosts():

    for node in config.Config.hosts():

        tag = "alive-%s" % node.host
        alive = execute.isAlive(node.addr) and "1" or "0"

        if tag in config.Config.state:
            previous = config.Config.state[tag]

            if alive != previous:
                util.output("host %s %s" % (node.host, alive == "1" and "up" or "down"))

        config.Config._setState(tag, alive)

def _getProfLogs():        

    dir = config.Config.statsdir
    if not os.path.exists(dir):
        os.mkdir(dir)

    if not os.path.exists(dir) or not os.path.isdir(dir):
        util.output("cannot create directory %s" % dir)
        return

    cmds = []

    for node in config.Config.hosts():
        cmd = os.path.join(config.Config.scriptsdir, "get-prof-log") + " %s %s %s/prof.log" % (node.tag, node.host, node.cwd())
        cmds += [(node, cmd, [], None)]

    for (node, success, output) in execute.runLocalCmdsParallel(cmds):
        if not success:
            util.output("cannot get prof.log from %s" % node.tag)

def _updateHTTPStats():

    # Get the prof.logs.
    _getProfLogs()

    # Copy stats.dat.
    shutil.copy(config.Config.statslog, config.Config.statsdir)

    # Creat meta file. 
    meta = open(os.path.join(config.Config.statsdir, "meta.dat"), "w")
    for node in config.Config.hosts():
        print >>meta, "node", node.tag, node.type, node.host

    print >>meta, "time", time.asctime()
    print >>meta, "version", config.Config.version

    try:
        print >>meta, "os", execute.captureCmd("uname -a")[1][0]
    except IndexError:
        print >>meta, "os <error>"

    try:
        print >>meta, "host", execute.captureCmd("hostname")[1][0]
    except IndexError:
        print >>meta, "host <error>"

    meta.close()



