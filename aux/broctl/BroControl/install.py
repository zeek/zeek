#! /usr/bin/env python
#
# $Id: install.py 6948 2009-12-03 20:59:41Z robin $
#
# Functions to install files on all nodes. 

import os
import sys
import glob
import fileinput

import util
import execute
import config

# In all paths given in this file, ${<option>} will replaced with the value of the
# corresponding configuration option.

# Directories to be created on the manager. Each entry is a pair (path, clean)
# in which 'clean' is a boolean indicating if True that the path is to be
# deleted first before it is freshly installed. 
Dirs = [
    ("${brobase}", False),
    ("${brobase}/share", False),
    ("${staticdir}", True),
    ("${logdir}", False),
    ("${bindir}", False),
    ("${scriptsdir}", False),
    ("${postprocdir}", False),
    ("${templatedir}", False),
    ("${helperdir}", False),
    ("${cfgdir}", False),

    ("${policydir}", False),
    ("${defsitepolicypath}", False),
    ("${policydirsiteinstall}", True),
    ("${policydirsiteinstallauto}", True),
    ("${policydirbroctl}", True),

    ("${spooldir}", False),
    ("${tmpdir}", False),
    ("${libdir}", False),
    ("${libdirinternal}", False),
    ("${libdirinternal}/BroControl", False),
    ]    

# Additional directories to be createdin development mode.     
DirsDev = [
     ("${policydir}/sigs", False),
     ("${policydir}/time-machine", False),
     ("${policydir}/xquery", False),
    ]

# List of files to be installed on the manager. Each entry is a pair
# (src, dst, replace). 'src' must be a file (globs are ok). 
# If replace is False, existing files will not be overwritten.
# If source ends in ".in", it's passed through option substitution and
# installed without the postfix.
#
# Note: all files ending in *.in will be copied first into ${templatedir}, and
# then from there into their final destination in substitized form. 
Targets = [ 
    ("${distdir}/aux/broctl/bin/broctl", "${bindir}", True),
    ("${distdir}/aux/broctl/aux/trace-summary/trace-summary", "${bindir}", True),
    ("${distdir}/aux/broctl/aux/capstats/capstats", "${bindir}", True),
    ("${distdir}/aux/broctl/BroControl/*.py", "${libdirinternal}/BroControl", True),
    ("${distdir}/aux/broctl/policy/*.bro", "${policydir}/broctl", True),
    ("${distdir}/aux/broctl/etc/analysis.dat", "${cfgdir}", True),
    ("${distdir}/aux/broctl/bin/run-bro.in", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/check-config.in", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/archive-log.in", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/delete-log", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/expire-logs.in", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/post-terminate.in", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/crash-diag.in", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/send-mail.in", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/mail-alarm.in", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/update.in", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/remove-log", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/is-alive.in", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/local-interfaces", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/cflow-stats.in", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/get-prof-log.in", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/mail-contents.in", "${scriptsdir}", True),
    ("${distdir}/aux/broctl/bin/helpers/start.in", "${helperdir}", True),
    ("${distdir}/aux/broctl/bin/helpers/stop", "${helperdir}", True),
    ("${distdir}/aux/broctl/bin/helpers/check-pid", "${helperdir}", True),
    ("${distdir}/aux/broctl/bin/helpers/top.in", "${helperdir}", True),
    ("${distdir}/aux/broctl/bin/helpers/get-childs", "${helperdir}", True),
    ("${distdir}/aux/broctl/bin/helpers/df.in", "${helperdir}", True),
    ("${distdir}/aux/broctl/bin/helpers/cat-file", "${helperdir}", True),
    ("${distdir}/aux/broctl/bin/helpers/run-cmd", "${helperdir}", True),
    ("${distdir}/aux/broctl/bin/helpers/to-bytes.awk", "${helperdir}", True),
    ("${distdir}/aux/broctl/bin/helpers/rmdir", "${helperdir}", True),
    ("${distdir}/aux/broctl/bin/helpers/is-dir", "${helperdir}", True),
    ("${distdir}/aux/broctl/bin/helpers/exists", "${helperdir}", True),  
    ("${distdir}/aux/broctl/bin/postprocessors/summarize-connections.in", "${postprocdir}", True),
    ("${distdir}/aux/broctl/bin/postprocessors/mail-log.in", "${postprocdir}", True),
    ("${distdir}/aux/broctl/.python-build/lib/_broccoli_intern.so", "${libdirinternal}", True),
    ("${distdir}/aux/broctl/.python-build/lib/broccoli.py", "${libdirinternal}", True),
    ("${distdir}/aux/broctl/.python-build/lib/_SubnetTree.so", "${libdirinternal}", True),
    ("${distdir}/aux/broctl/.python-build/lib/SubnetTree.py", "${libdirinternal}", True),
]

# Additional list of files only copied when in development mode. 
TargetsDev = [
    # Note that the paths here should match with match Bro's "make install" is
    # doing.
    ("${distdir}/src/bro", "${bindir}/bro", True),
    ("${distdir}/policy/*.bro", "${policydir}", True),
    ("${distdir}/policy/bro.init", "${policydir}", True),
    ("${distdir}/policy/sigs/*.sig", "${policydir}/sigs", True),
    ("${distdir}/policy/time-machine/*.bro", "${policydir}/time-machine", True),
    ("${distdir}/policy/xquery/*.xq", "${policydir}/xquery", True),
    ("${distdir}/aux/broccoli/src/.libs/lib*", "${libdir}", True),
]

# Do not complain if these source files do no exist.
OptionalTargets = [
    ("${distdir}/aux/cf/cf", "${bindir}", True),
    ("${distdir}/aux/hf/hf", "${bindir}", True),
]

# Diretories/files in form (path, mirror) which are synced from the manager to all nodes. 
# If 'mirror' is true, the path is fully mirrored recursively, otherwise the 
# directory is just created.
Syncs = [
    ("${brobase}", False),
    ("${brobase}/share", True),
    ("${cfgdir}", True),
    ("${libdir}", True),
    ("${bindir}", True),
    # ("${policydir}", True),
    # ("${staticdir}", True),
    ("${logdir}", False),
    ("${spooldir}", False),
    ("${tmpdir}", False),
    ];    

def _canonTarget(file, dst):
    manager = config.Config.manager()
    if execute.isdir(manager, dst):
        target = os.path.join(dst, os.path.basename(file))
    else:
        target = dst

    subst = False
    if target.endswith(".in"):
        target = target[:-3]
        subst = True

    if file.endswith(".in"):
        subst = True

    return (target, subst)

# Performs the complete broctl installion process.
# 
# If local_only is True, nothing is propagated to other nodes.
# If make_install is True, the install adapts for usage from a "make install",
# i.e., it will copy all the static files form the broctl distribution; if
# False, it will perform the "broctl install" command which only updates
# dynamically generated files plus the site policy. In development mode,
# "make_install" is always overridden to be True.
def install(local_only, make_install):
    if config.Config.devmode == "1":
        make_install = True

    config.Config.determineBroVersion()

    manager = config.Config.manager()

    # Delete previously installed policy files to not mix things up.
    policies = [config.Config.policydirsiteinstall, config.Config.policydirsiteinstallauto]

    if make_install:
        policies += [config.Config.subst("${policydir}/broctl")]

    for p in policies:
        if os.path.isdir(p):
            util.output("removing old policies in %s ..." % p, False)
            execute.rmdir(manager, p)
            util.output(" done.")


    util.output("creating policy directories ...", False)
    for p in policies:
        execute.mkdir(manager, p)
    util.output(" done.")

    custom = [(os.path.expanduser(file), "${bindir}", True, False) for file in config.Config.custominstallbin.split()]
    pp = [(os.path.expanduser(file), "${postprocdir}", True, False) for file in config.Config.auxpostprocessors.split()]

    targets = Targets
    if config.Config.devmode == "1":
        targets += TargetsDev

    mandatory = [(src, dst, replace, False) for (src, dst, replace) in targets]
    optional  = [(src, dst, replace, True) for (src, dst, replace) in OptionalTargets]

    if config.Config.standalone == "0":
        mandatory += [("${distdir}/aux/broctl/etc/node.cfg.cluster.in", "${cfgdir}/node.cfg.example", False, False)]
        mandatory += [("${distdir}/aux/broctl/etc/broctl.cfg.cluster.in", "${cfgdir}/broctl.cfg.example", False, False)]
        mandatory += [("${distdir}/aux/broctl/etc/networks.cfg.in", "${cfgdir}/networks.cfg.example", False, True)]
        mandatory += [("${distdir}/aux/broctl/policy/local/cluster.local-manager.bro-template", "${defsitepolicypath}/local-manager.bro", False, True)]
        mandatory += [("${distdir}/aux/broctl/policy/local/cluster.local-worker.bro-template", "${defsitepolicypath}/local-worker.bro", False, True)]
        mandatory += [("${distdir}/aux/broctl/policy/local/cluster.local.bro-template", "${defsitepolicypath}/local.bro", False, True)]
    else:
        mandatory += [("${distdir}/aux/broctl/etc/node.cfg.standalone.in", "${cfgdir}/node.cfg", False, False)]
        mandatory += [("${distdir}/aux/broctl/etc/broctl.cfg.standalone.in", "${cfgdir}/broctl.cfg", False, False)]
        mandatory += [("${distdir}/aux/broctl/etc/networks.cfg.in", "${cfgdir}/networks.cfg", False, True)]
        mandatory += [("${distdir}/aux/broctl/policy/local/standalone.local.bro-template", "${defsitepolicypath}/local.bro", False, True)]

    all_targets = mandatory + optional + custom + pp

    if make_install:
        util.output("creating installation directories ...", False)
        # Install the static parts of the broctl distribution. 
        dirs = Dirs
        if config.Config.devmode == "1":
            dirs += DirsDev

        for (dir, clean) in dirs:
            dir = config.Config.subst(dir)
            if clean:
                execute.rmdir(manager, dir)

            execute.mkdir(manager, dir)

        util.output(" done.")

        # Copy files.
        util.output("installing files ...", False)

        for (src, dst, replace, optional) in all_targets:
            src = config.Config.subst(src)
            dst = config.Config.subst(dst)

            files = glob.glob(src)
            if not files and not optional: 
                util.warn("file does not exist: %s" % src)
                continue

            for file in files:
                (target, subst) = _canonTarget(file, dst)

                if not replace and execute.exists(manager, target):
                    continue

                if subst:
                    # Installation copies to template directory only.
                    # Substitution will be performed later. 
                    target = config.Config.templatedir

                if not execute.install(manager, file, target):
                    continue

        if manager:
            if not execute.mkdir(manager, manager.cwd()):
                util.warn("cannot create %s on manager" % manager.cwd())

        util.output(" done.")

    # Processing the templates by substitung all variables.
    for (src, dst, replace, optional) in all_targets:
        # Doesn't work with globs!

        src = config.Config.subst(src)
        dst = config.Config.subst(dst)
        file = os.path.join(config.Config.templatedir, os.path.basename(src))

        if not execute.exists(manager, file):
            continue

        (target, subst) = _canonTarget(file, dst)

        assert subst

        if not replace and execute.exists(manager, target):
            continue

        if not execute.install(manager, file, target):
            continue

        for line in fileinput.input(target, inplace=1):
            print config.Config.subst(line, make_dest=False),
        fileinput.close()

    # Install local site policy.

    if config.Config.sitepolicypath:
        util.output("installing site policies ...", False)
        dst = config.Config.policydirsiteinstall
        for dir in config.Config.sitepolicypath.split(":"):
            dir = config.Config.subst(dir)
            for file in glob.glob(os.path.join(dir, "*")):
                if execute.isfile(manager, file):
                    execute.install(manager, file, dst)
        util.output(" done.")

    if not config.Config.nodes():
        if config.Config.standalone == "0":
            return

        # The standalone installs default configs. Start over to read those.
        util.output("[second install pass]")
        os.system(config.Config.subst("${bindir}/broctl install"))
        config.Config.readState()
        config.Config._readNodes()
        return

    makeLayout()
    makeAnalysisPolicy()
    makeLocalNetworks()

    current = config.Config.subst(os.path.join(config.Config.logdir, "current"), make_dest=False)
    if not execute.exists(manager, current):
        try:
            os.symlink(manager.cwd(), current)
        except (IOError, OSError), e:
            util.warn("cannot link %s to %s: %s" % (manager.cwd(), current, e))

    if local_only:
        return

    # Sync to clients.
    util.output("updating nodes ... ", False)

    hosts = {}
    nodes = []

    for n in config.Config.nodes():
        # Make sure we do each host only once.
        if n.host in hosts:
            continue

        hosts[n.host] = 1

        if n == manager:
            continue

        if not execute.isAlive(n.addr):
            continue

        nodes += [n]

    if config.Config.havenfs != "1":
        # Non-NFS, need to explicitly synchronize.
        dirs = []
        for dir in [config.Config.subst(dir) for (dir, mirror) in Syncs if not mirror]:
            dirs += [(n, dir) for n in nodes]

        for (node, success) in execute.mkdirs(dirs):
            if not success:
                util.warn("cannot create directory %s on %s" % (dir, node.tag))

        paths = [config.Config.subst(dir) for (dir, mirror) in Syncs if mirror]                
        execute.sync(nodes, paths)
        util.output("done.")

        # Note: the old code created $brobase explicitly but it seems the loop above should 
        # already take care of that.

    else:
        # NFS. We only need to take care of the spool/log directoryies.
        paths = [config.Config.spooldir]
        paths += [config.Config.logdir]

        dirs = []
        for dir in paths:
            dirs += [(n, dir) for n in nodes]

        for (node, success) in execute.mkdirs(dirs):
            if not success:
                util.warn("cannot create directory on %s" % (dir, node.tag))
        util.output("done.")

# Create Bro-side broctl configuration broctl-layout.bro.        

port = -1

def makeLayout():
    def nextPort(node):
        global port
        port += 1
        node.setPort(port)
        return port

    global port
    port = 47759
    manager = config.Config.manager()

    if not manager:
        return

    util.output("generating broctl-layout.bro ...", False)

    out = open(os.path.join(config.Config.policydirsiteinstallauto, "broctl-layout.bro"), "w")
    print >>out, "# Automatically generated. Do not edit.\n"
    print >>out, "redef BroCtl::manager = [$ip = %s, $p=%s/tcp, $tag=\"%s\"];\n" % (manager.addr, nextPort(manager), manager.tag);

    proxies = config.Config.nodes("proxy")
    print >>out, "redef BroCtl::proxies = {"
    for p in proxies:
        tag = p.tag.replace("proxy-", "p")
        print >>out, "\t[%d] = [$ip = %s, $p=%s/tcp, $tag=\"%s\"]," % (p.count, p.addr, nextPort(p), tag)
    print >>out, "};\n"

    workers = config.Config.nodes("worker")
    print >>out, "redef BroCtl::workers = {"
    for s in workers:
        tag = s.tag.replace("worker-", "w")
        p = s.count % len(proxies) + 1
        print >>out, "\t[%d] = [$ip = %s, $p=%s/tcp, $tag=\"%s\", $interface=\"%s\", $proxy=BroCtl::proxies[%d]]," % (s.count, s.addr, nextPort(s), tag, s.interface, p)
    print >>out, "};\n"

    print >>out, "redef BroCtl::log_dir = \"%s\";\n" % config.Config.subst(config.Config.logdir, make_dest=False)
	
    # Activate time-machine support if configured.
    if config.Config.timemachinehost:
        print >>out, "redef BroCtl::tm_host = %s;\n" % config.Config.timemachinehost
        print >>out, "redef BroCtl::tm_port = %s;\n" % config.Config.timemachineport
        print >>out

    util.output(" done.")

# Create Bro script to enable the selected types of analysis.
def makeAnalysisPolicy():
    manager = config.Config.manager()

    if not manager:
        return

    util.output("generating analysis-policy.bro ...", False)

    out = open(os.path.join(config.Config.policydirsiteinstallauto, "analysis-policy.bro"), "w")
    print >>out, "# Automatically generated. Do not edit.\n"

    disabled_event_groups = []
    booleans = []
    warns = []

    analysis = config.Config.analysis()
    redo = False

    for (type, state, mechanisms, descr) in analysis.all():

        for mechanism in mechanisms.split(","):

            try:
                i = mechanism.index(":")
                scheme = mechanism[0:i]
                arg = mechanism[i+1:]
            except ValueError:
                util.warn("error in %s: ignoring mechanism %s" % (config.Config.analysiscfg, mechanism))
                continue

            if scheme == "events":
                # Default is on so only need to record those which are disabled.
                if not state:
                    disabled_event_groups += [type]

            elif scheme == "bool":
                booleans += [(arg, state)]

            elif scheme == "bool-inv":
                booleans += [(arg, not state)]

            elif scheme == "disable":
                if state:
                    continue

                if not analysis.isValid(arg):
                    util.warn("error in %s: unknown type '%s'" % (config.Config.analysiscfg, arg))
                    continue

                if analysis.isEnabled(arg):
                    warns += ["disabled analysis %s (depends on %s)" % (arg, type)]
                    analysis.toggle(arg, False)
                    redo = True

            else:
                util.warn("error in %s: ignoring unknown mechanism scheme %s" % (config.Config.analysiscfg, scheme))
                continue

    if disabled_event_groups:
        print >>out, "redef AnalysisGroups::disabled_groups = {"
        for g in disabled_event_groups:
            print >>out, "\t\"%s\"," % g
        print >>out, "};\n"

    for (var, val) in booleans:
        print >>out, "@ifdef ( %s )" % var
        print >>out, "redef %s = %s;" % (var, val and "T" or "F");
        print >>out, "@endif\n" 
    print >>out, "\n"

    out.close()

    util.output(" done.")

    for w in warns:
        util.warn(w)

    if redo:
        # Second pass.
        makeAnalysisPolicy()

# Reads in a list of networks from file.
def readNetworks(file):

    nets = []

    for line in open(file):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        fields = line.split()
        nets += [(fields[0], " ".join(fields[1:]))]

    return nets


# Create Bro script which contains a list of local networks. 
def makeLocalNetworks():

    netcfg = config.Config.localnetscfg

    if not os.path.exists(netcfg):
        if not config.Installing:
            util.warn("list of local networks does not exist in %s" % netcfg)
        return

    util.output("generating local-networks.bro ...", False)

    out = open(os.path.join(config.Config.policydirsiteinstallauto, "local-networks.bro"), "w")
    print >>out, "# Automatically generated. Do not edit.\n"

    netcfg = config.Config.localnetscfg

    if os.path.exists(netcfg):
        nets = readNetworks(netcfg)

        print >>out, "redef local_nets = {"
        for (cidr, tag) in nets:
            print >>out, "\t%s," % cidr,
            if tag != "":
                print >>out, "\t# %s" % tag,
            print >>out
        print >>out, "};\n"

    util.output(" done.")



