#! /usr/bin/env python
#
# $Id: config.py 6948 2009-12-03 20:59:41Z robin $
#
# Functions to read and access the broctl configuration.

import os
import sys
import socket
import imp
import re

import ConfigParser

import options
import execute
import util

# One broctl node. 
class Node:

    # Valid tags in nodes file. The values will be stored 
    # in attributes of the same name.
    _tags = { "type": 1, "host": 1, "interface": 1, "aux_scripts": 1, "brobase": 1, "ether": 1 }

    def __init__(self, tag):
        self.tag = tag

    def __str__(self):
        def fmt(v):
            if type(v) == type([]):
                v = ",".join(v)
            return v

        return ("%15s - " % self.tag) + " ".join(["%s=%s" % (k, fmt(self.__dict__[k])) for k in sorted(self.__dict__.keys())])

    # Returns the working directory for this node. 
    def cwd(self):
        return os.path.join(Config.spooldir, self.tag)

    # Stores the nodes process ID. 
    def setPID(self, pid):
        Config._setState("%s-pid" % self.tag, str(pid))

    # Returns the stored process ID.
    def getPID(self):
        t = "%s-pid" % self.tag
        if t in Config.state:
            return Config.state[t]
        return None

    # Unsets the stored process ID.
    def clearPID(self):
        Config._setState("%s-pid" % self.tag, "")

    # Mark node as having terminated unexpectedly.
    def setCrashed(self):
        Config._setState("%s-crashed" % self.tag, "1")

    # Unsets the flag for unexpected termination.
    def clearCrashed(self):
        Config._setState("%s-crashed" % self.tag, "0")

    # Returns true if node has terminated unexpectedly.
    def hasCrashed(self):
        t = "%s-crashed" % self.tag
        return t in Config.state and Config.state[t] == "1"

    # Set the Bro port this node is using.
    def setPort(self, port):
        Config._setState("%s-port" % self.tag, str(port))

    # Get the Bro port this node is using.
    def getPort(self):
        t = "%s-port" % self.tag
        return t in Config.state and int(Config.state[t]) or -1

# Class managing types of analysis. 
class Analysis:
    def __init__(self, cfgfile):

        self.types = {}
        cnt = 0

        if not os.path.exists(cfgfile):
            if Installing:
                return

            util.error("analysis configuration %s does not exist" % cfgfile)

        for line in open(cfgfile):
            cnt += 1
            line = line.strip()
            if not line or line.startswith("#"): 
                continue

            f = line.split()
            if len(f) < 2:
                util.warn("cannot parse line %d in %s" % (cnt, cfgfile))
                continue

            type = f[0]
            mechanism = f[1]
            descr = ""
            if len(f) > 2:
                descr = " ".join(f[2:])

            self.types[type] = (mechanism, descr)

    # Returns true if we know this kind of analysis.
    def isValid(self, type):
        return type in self.types

    # Returns true if type is enabled.
    # Default is yes if we haven't disabled it.
    def isEnabled(self, type):
        tag = "analysis-%s" % type
        try:
            return int(Config.state[tag]) != 0
        except KeyError:
            return True

    # Enable/disable type.
    def toggle(self, type, enable=True):
        tag = "analysis-%s" % type
        if enable:
            try:
                del Config.state[tag]
            except KeyError:
                pass
        else:
            Config.state[tag] = 0

    # Returns tuples (type, status, mechanism, descr) of all known analysis types.
    # 'type' is tag for analysis.
    # 'status' is True if analysis is activated.
    # 'mechanism' gives the method how to control the analysis within Bro (see etc/analysis.dat).
    # 'descr' is textual dscription for the kind of analysis.
    def all(self):
        result = []
        keys = self.types.keys()
        keys.sort()
        for type in keys:
            (mechanism, descr) = self.types[type]
            result += [(type, self.isEnabled(type), mechanism, descr)]
        return result

# Class storing the broctl configuration.
#
# This class provides access to four types of configuration/state:
#
# - the global broctl configuration from broctl.cfg
# - the node configuration from nodes.cfg
# - dynamic state variables which are kept across restarts in spool/broctl.dat
# - types of analysis which can be toggled via the shell

Config = None # Globally accessible instance of Configuration.
Installing = False
BroBase = None
MakeDestDir = None

class Configuration:    
    def __init__(self, config, basedir, distdir, version, standalone):
        global Config
        global Installing

        Config = self

        if "BROCTL_INSTALL" in os.environ:
            Installing = True
            
            global BroBase
            BroBase = basedir
            
            if "MAKE_DESTDIR" in os.environ:
                global MakeDestDir
                MakeDestDir = os.environ["MAKE_DESTDIR"]

        self.config = {}
        self.state = {}

        # Read broctl.cfg.
        self.config = self._readConfig(os.path.join(basedir, config))

        # Set defaults for options we get passed in.
        self._setOption("brobase", basedir)
        self._setOption("distdir", distdir)
        self._setOption("version", version)
        self._setOption("standalone", standalone and "1" or "0")
		
		# Initialize options.
        for opt in options.options:
            if not opt.dontinit:
                self._setOption(opt.name.lower(), opt.default)
		
		# Set defaults for options we derive dynamically.
		self._setOption("mailto", "%s" % os.getenv("USER"))
		self._setOption("mailfrom", "Big Brother <bro@%s>" % socket.gethostname())
		self._setOption("home", os.getenv("HOME"))
		self._setOption("mailalarmsto", self.config["mailto"]) 
		
        # Determine operating system.
        (success, output) = execute.captureCmd("uname")
        if not success:
            util.error("cannot run uname")
        self._setOption("os", output[0].lower().strip())

        # Find the time command (should be a GNU time for best results).
        (success, output) = execute.captureCmd("which time")
        self._setOption("time", output[0].lower().strip())
		
        # Read nodes.cfg and broctl.dat.
        self._readNodes()
        self.readState()

        # Setup the kinds of analyses which we support.
        self._analysis = Analysis(self.analysiscfg)

        # Make sure cron flag is cleared.
        self.config["cron"] = "0"

    # Provides access to the configuration options via the dereference operator.
    # Lookups the attribute in broctl.cfg first, then in the dynamic variables from broctl.dat.
    # Defaults to empty string for unknown options.
    def __getattr__(self, attr):
        if attr in self.config:
            return self.config[attr]
        if attr in self.state:
            return self.state[attr]
        return ""

    # Returns True if attribute is defined.
    def hasAttr(self, attr):
        if attr in self.config:
            return True
        if attr in self.state:
            return True
        return False

    # Returns a list of all broctl.cfg entries.
    # Includes dynamic variables if dynamic is true.
    def options(self, dynamic=True):
        if dynamic:
            return self.config.items() + self.state.items()
        else:
            return self.config.items()

    # Returns a list of Nodes. 
    # - If tag is "global" or "all", all Nodes are returned if "expand_all" is true.
    #     If "expand_all" is false, returns an empty list in this case.
    # - If tag is "proxies" or "proxy", all proxy Nodes are returned.
    # - If tag is "workers" or "worker", all worker Nodes are returned.
    # - If tag is "manager", the manager Node is returned.
    def nodes(self, tag=None, expand_all=True):
        nodes = []
        type = None

        if tag == "cluster" or tag == "all":
            if not expand_all:
                return []

            tag = None

        if tag == "proxies":
            tag = "proxy"

        if tag == "workers":
            tag = "worker"

        if ("scripts-%s" % tag) in self.config:
            type = tag

        for n in self.nodelist.values():

            if type:
                if type == n.type:
                    nodes += [n]

            elif tag == n.tag or not tag:
                nodes += [n]

        nodes.sort(key=lambda n: (n.type, n.tag))

        if not nodes and tag == "manager":
            nodes = self.nodes("standalone")

        return nodes

    # Returns the manager Node.
    def manager(self):
        n = self.nodes("manager")
        if n:
            return n[0]
        n = self.nodes("standalone")
        if n:
            return n[0]
        return None

    # Returns a list of nodes which is a subset of the result a similar call to
    # nodes() would yield but within which each host appears only once.
    def hosts(self, tag = None):
        hosts = {}
        for node in self.nodes(tag):
            if not node.host in hosts:
                hosts[node.host] = node

        return hosts.values()

    # Replace all occurences of "${option}", with option being either
    # broctl.cfg option or a dynamic variable, with the corresponding value. 
    # Defaults to replacement with the empty string for unknown options.
    def subst(self, str, make_dest=True):
        while True:
            m = re.search(r"(\$\{([A-Za-z]+)(:([^}]+))?\})", str)
            if not m:
                
                # This is a hack to support make's DESTDIR: if the env variable
                # MAKE_DESTDIR is set, and the string we return starts with  our
                # installation prefix, we prepend the var's content. This it not
                # totally perfect but should do the trick.
                if Installing and MakeDestDir and MakeDestDir != "":
                    
                    if make_dest and str.startswith(BroBase):
                        str = MakeDestDir + str

                    if not make_dest:
                        str = str.replace(MakeDestDir, "")
                    
                return str

            key = m.group(2).lower()
            if self.hasAttr(key):
                value = self.__getattr__(key)
            else:
                value = m.group(4)

            if not value:
                value = ""

            str = str[0:m.start(1)] + value + str[m.end(1):]

    # Returns instance of class Analysis. 
    def analysis(self):
        return self._analysis

    # Parse nodes.cfg.
    def _readNodes(self):
        self.nodelist = {}
        config = ConfigParser.SafeConfigParser()
        if not config.read(self.nodecfg) and not Installing:
            util.error("cannot read '%s'" % self.nodecfg)

        manager = False
        proxy = False
        standalone = False

        file = self.nodecfg

        counts = {}
        for sec in config.sections():

            node = Node(sec)
            self.nodelist[sec] = node

            for (key, val) in config.items(sec):
                if not key in Node._tags:
                    util.warn("%s: unknown key '%s' in section '%s'" % (file, key, sec))
                    continue

                if key == "type":
                    # We determine which types are valid by checking for having an
                    # option specifying which scripts to use for it.
                    cfg = "scripts-%s" % val 
                    if not cfg  in self.config:
                        util.error("%s: unknown type '%s' in section '%s'" % (file, val, sec))

                    self.nodelist[sec].scripts = self.config[cfg].split()

                    if val == "manager":
                        if manager:
                            util.error("only one manager can be defined")
                        manager = True

                    if val == "proxy":
                        proxy = True

                    if val == "standalone":
                        standalone = True

                node.__dict__[key] = val

            try:
                node.addr = socket.gethostbyname(node.host)
            except AttributeError:
                util.error("%s: no host given in section '%s'" % (file, sec))
            except socket.gaierror, e:
                util.error("%s: unknown host '%s' in section '%s' [%s]" % (file, node.host, sec, e.args[1]))

            # Each node gets a number unique across its type.
            type = self.nodelist[sec].type
            try: 
                counts[type] += 1
            except KeyError:
                counts[type] = 1

            node.count = counts[type]

        if self.nodelist:

            if not standalone:
                if not manager:
                    util.error("%s: no manager defined" % file)

                if not proxy:
                    util.error("%s: no proxy defined" % file)

            else:
                if len(self.nodelist) > 1:
                    util.error("%s: more than one node defined in stand-alone setup" % file)

        for n in self.nodelist.values():
            if n.type == "manager":
                if not execute.isLocal(n):
                    util.error("script must be run on manager node")

                if n.addr == "127.0.0.1" and n.type != "standalone":
                    util.error("cannot use localhost/127.0.0.1 for manager host in nodes configuration")


    # Parses broctl.cfg and returns a dictionary of all entries. 
    def _readConfig(self, file):
        config = {}
        try:
            for line in open(file):

                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                args = line.split("=")
                if len(args) != 2:
                    util.error("%s: syntax error '%s'" % (file, line))

                (key, val) = args
                key = key.strip().lower()
                val = val.strip()

                config[key] = val

        except IOError, e:
            if not Installing:
                util.error("cannot read '%s'" % file)

        return config

    # Initialize a global option if not already set.
    def _setOption(self, val, key):
        if not val in self.config:
            self.config[val] = self.subst(key)

    # Set a dynamic state variable.
    def _setState(self, val, key):
        self.state[val] = key

    # Read dynamic state variables from {$spooldir}/broctl.dat .
    def readState(self):
        self.state = self._readConfig(self.statefile)

    # Write the dynamic state variables into {$spooldir}/broctl.dat .
    def writeState(self):
        try:
            out = open(self.statefile, "w")
        except IOError:
            if not Installing:
                util.warn("can't write '%s'" % self.statefile)
            return

        print >>out, "# Automatically generated. Do not edit.\n"

        for (key, val) in self.state.items():
            print >>out, "%s = %s" % (key, self.subst(str(val), make_dest=False))

    # Runs Bro to get its version numbers.
    def determineBroVersion(self):
        version = None
        bro = os.path.join(self.distdir, "src/bro")
        if execute.exists(None, bro):
            (success, output) = execute.captureCmd("%s -v 2>&1" % bro)
            if success:
                version = output[0]

        if not version:
            # Ok if it's already set. 
            if "broversion" in self.state:
                return

            util.error("cannot find Bro binary to determine version")

        m = re.search(".* version ([^ ]*).*$", version)
        if not m:
            util.error("cannot determine Bro version [%s]" % version.strip())

        version = m.group(1)
        if version.endswith("-debug"):
            version = version[:-6]

        self.state["broversion"] = version
        self.state["bro"] = self.subst("${bindir}/bro")

    # Returns true if we're running via "make install"
    def installing(self):
        return Installing

