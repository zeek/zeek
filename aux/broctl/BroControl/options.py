# $Id: options.py 6813 2009-07-07 18:54:12Z robin $
#
# Configuration options. 
#
# If started directly, will print option reference documentation.

class Option:

    # Options category.
    USER = 1       # Standard user-configurable option.
    INTERNAL = 2   # internal, don't expose to user. 
    AUTOMATIC = 3  # Set automatically, unlikely to be changed.

    def __init__(self, name, default, type, category, dontinit, description):
        self.name = name
        self.default = default
        self.type = type
        self.dontinit = dontinit
        self.category = category
        self.description = description

options = [
    # User options.
    Option("Debug", "0", "bool", Option.USER, False, 
           "Enable extensive debugging output in spool/debug.log."),

    Option("HaveNFS", "0", "bool", Option.USER, False, 
           "True if shared files are mounted across all nodes via NFS (see FAQ)."),
    Option("SaveTraces", "0", "bool", Option.USER, False,
           "True to let backends capture short-term traces via '-w'. These are not archived but might be helpful for debugging."),
    Option("DevMode", "0", "bool", Option.USER, False,
           "Enable development mode, which changes how things are installed by the _install_ command."),

    Option("LogDir", "${BroBase}/logs", "string", Option.USER, False,
           "Directory for archived log files."),

    Option("SendMail", "1", "bool", Option.USER, False,
           "True if shell may send mails."),
    Option("MailSubjectPrefix", "[Bro]", "string", Option.USER, False,
           "General Subject prefix for broctl-generated mails."),
    Option("MailAlarmPrefix", "ALERT:", "string", Option.USER, False,
           "Subject prefix for individual alerts triggered by NOTICE_EMAIL."),
    Option("MailReplyTo", "", "string", Option.USER, False,
           "Reply-to address for broctl-generated mails."),
    Option("MailTo", "<user>", "string", Option.USER, True,
           "Destination address for broctl-generated non-alarm mails. Default is to use the same address as +MailTo+."),
    Option("MailAlarmsTo", "${MailTo}", "string", Option.USER, True,
           "Destination address for broctl-generated alarm mails."),
    Option("MailFrom", "Big Brother <bro@localhost>", "string", Option.USER, True,
           "Originator address for broctl-generated mails."),

    Option("MailAlarms", "1", "bool", Option.USER, False,
           "True if Bro should send mails for NOTICE_EMAIL alerts."),
    Option("MinDiskSpace", "5", "int", Option.USER, False,
           "Percentage of minimum disk space available before warning is mailed."),
    Option("LogExpireInterval", "30", "int", Option.USER, False,
           "Number of days log files are kept."),
    Option("BroArgs", "", "string", Option.USER, False,
           "Additional arguments to pass to Bro on the command-line."),
    Option("MemLimit", "unlimited", "string", Option.USER, False,
           "Maximum amount of memory for Bro processes to use (in KB, or the string 'unlimited')."),

    Option("TimeFmt", "%d %b %H:%M:%S", "string", Option.USER, False,
           "Format string to print data/time specifications (see 'man strftime')."),

    Option("Prefixes", "local", "string", Option.USER, False,
           "Additional script prefixes for Bro, separated by colons. Use this instead of @prefix."),

    Option("AuxScriptsManager", "", "string", Option.USER, False,
           "Additional Bro scripts loaded on the manager, separated by spaces."),
    Option("AuxScriptsWorker", "", "string", Option.USER, False,
           "Additional Bro scripts loaded on the workers, separated by spaces."),
    Option("AuxScriptsStandalone", "", "string", Option.USER, False,
           "Additional Bro scripts loaded on a standalone Brothe manage, separated by spaces."),

    Option("AuxPostProcessors", "", "string", Option.USER, False,
           "Additional log postprocessors, with paths separated by spaces."),

    Option("SitePolicyManager", "local-manager.bro", "string", Option.USER, False,
           "Local policy file for manager."),
    Option("SitePolicyWorker", "local-worker.bro", "string", Option.USER, False,
           "Local policy file for workers."),
    Option("SitePolicyStandalone", "local.bro", "string", Option.USER, False,
           "Local policy file for standalone Bro."),

    Option("CustomInstallBin", "", "string", Option.USER, False,
           "Additional executables to be installed into ${BinDir}, including full path and separated by spaces."),

    Option("CronCmd", "", "string", Option.USER, False,
           "A custom command to run everytime the cron command has finished."),

    Option("CFlowAddr", "", "string", Option.USER, False,
           "If a cFlow load-balander is used, the address of the device (format: <ip>:<port>)."),
    Option("CFlowUser", "", "string", Option.USER, False,
           "If a cFlow load-balander is used, the user name for accessing its configuration interface."),
    Option("CFlowPassword", "", "string", Option.USER, False,
           "If a cFlow load-balander is used, the password for accessing its configuration interface."),
		   
    Option("TimeMachineHost", "", "string", Option.USER, False,
           "If the manager should connect to a Time Machine, the address of the host it is running on."),
    Option("TimeMachinePort", "47757/tcp", "string", Option.USER, False,
           "If the manager should connect to a Time Machine, the port it is running on (in Bro syntax, e.g., +47757/tcp+."),
		
    # Automatically set.
    Option("BroBase", "", "string", Option.AUTOMATIC, True, 
           "Base path of broctl installation on all nodes."),
    Option("DistDir", "", "string", Option.AUTOMATIC, True, 
           "Path to Bro distribution directory."),
    Option("Version", "", "string", Option.AUTOMATIC, True, 
           "Version of the broctl."),
    Option("StandAlone", "0", "bool", Option.AUTOMATIC, True, 
           "True if running in stand-alone mode (see elsewhere)."),
    Option("OS", "", "string", Option.AUTOMATIC, True, 
           "Name of operation systems as reported by uname."),
    Option("Time", "", "string", Option.AUTOMATIC, True, 
           "Path to time binary."),

    Option("HaveBroccoli", "", "bool", Option.AUTOMATIC, False,
           "True if Broccoli interface is available."),

    Option("BinDir", "${BroBase}/bin", "string", Option.AUTOMATIC, False,
           "Directory for executable files."),
    Option("ScriptsDir", "${BroBase}/share/broctl/scripts", "string", Option.AUTOMATIC, False,
           "Directory for executable scripts shipping as part of broctl."),
    Option("PostProcDir", "${BroBase}/share/broctl/scripts/postprocessors", "string", Option.AUTOMATIC, False,
           "Directory for log postprocessors."),
    Option("HelperDir", "${BroBase}/share/broctl/scripts/helpers", "string", Option.AUTOMATIC, False,
           "Directory for broctl helper scripts."),
    Option("CfgDir", "${BroBase}/etc", "string", Option.AUTOMATIC, False,
           "Directory for configuration files."),
    Option("SpoolDir", "${BroBase}/spool", "string", Option.AUTOMATIC, False,
           "Directory for run-time data."),
    Option("PolicyDir", "${BroBase}/share/bro", "string", Option.AUTOMATIC, False,
           "Directory for standard policy files."),
    Option("StaticDir", "${BroBase}/share/broctl", "string", Option.AUTOMATIC, False,
           "Directory for static, arch-independent files."),
    Option("TemplateDir", "${BroBase}/share/broctl/templates", "string", Option.AUTOMATIC, False,
           "Directory where the *.in templates are copied into."),

    Option("LibDir", "${BroBase}/lib", "string", Option.AUTOMATIC, False,
           "Directory for library files."),
    Option("LibDirInternal", "${BroBase}/lib/broctl", "string", Option.AUTOMATIC, False,
           "Directory for broctl-specific library files."),
    Option("TmpDir", "${SpoolDir}/tmp", "string", Option.AUTOMATIC, False,
           "Directory for temporary data."),
    Option("TmpExecDir", "${SpoolDir}/tmp", "string", Option.AUTOMATIC, False,
           "Directory where binaries are copied before execution."),
    Option("StatsDir", "${LogDir}/stats", "string", Option.AUTOMATIC, False,
           "Directory where statistics are kepts."),

    Option("TraceSummary", "${bindir}/trace-summary", "string", Option.AUTOMATIC, False, 
           "Path to trace-summary script; empty if not available."),
    Option("Capstats", "${bindir}/capstats", "string", Option.AUTOMATIC, False, 
           "Path to capstats binary; empty if not available."),

    Option("NodeCfg", "${CfgDir}/node.cfg", "string", Option.AUTOMATIC, False,
           "Node configuration file."),
    Option("LocalNetsCfg", "${CfgDir}/networks.cfg", "string", Option.AUTOMATIC, False,
           "File definining the local networks."),
    Option("AnalysisCfg", "${CfgDir}/analysis.dat", "string", Option.AUTOMATIC, False,
           "Configuration file defining types of analysis which can be toggled on-the-fly."),
    Option("StateFile", "${SpoolDir}/broctl.dat", "string", Option.AUTOMATIC, False,
           "File storing the current broctl state."),
    Option("LockFile", "${SpoolDir}/lock", "string", Option.AUTOMATIC, False,
           "Lock file preventing concurrent shell operations."),

    Option("DebugLog", "${SpoolDir}/debug.log", "string", Option.AUTOMATIC, False,
           "Log file for debugging information."),
    Option("StatsLog", "${SpoolDir}/stats.log", "string", Option.AUTOMATIC, False,
           "Log file for statistics."),

    Option("SitePolicyPath", "${PolicyDir}/site", "string", Option.USER, False,
           "Directories to search for local policy files, separated by colons."),           

    Option("DefSitePolicyPath", "${PolicyDir}/site", "string", Option.INTERNAL, False,
           "Default directory to search for local policy files."),           

    Option("PolicyDirSiteInstall", "${PolicyDir}/.site", "string", Option.AUTOMATIC, False,
           "Directory where the shell copies local policy scripts when installing."),
    Option("PolicyDirSiteInstallAuto", "${PolicyDir}/.site/auto", "string", Option.AUTOMATIC, False,
           "Directory where the shell copies auto-generated local policy scripts when installing."),
    Option("PolicyDirBroCtl", "${PolicyDir}/broctl", "string", Option.AUTOMATIC, False,
           "Directory where the shell copies the additional broctl policy scripts when installing."),

    Option("Scripts-Manager", "cluster-manager", "string", Option.AUTOMATIC, False,
           "Bro scripts loaded on the manager, separated by spaces."),
    Option("Scripts-Worker", "cluster-worker", "string", Option.AUTOMATIC, False,
           "Bro scripts loaded on the workers, separated by spaces."),
    Option("Scripts-Proxy", "cluster-proxy", "string", Option.AUTOMATIC, False,
           "Bro scripts loaded on the proxies, separated by spaces."),
    Option("Scripts-Standalone", "standalone", "string", Option.AUTOMATIC, False,
           "Bro scripts loaded on a standalone Bro, separated by spaces."),

    # Internal, not documented. 
    Option("SigInt", "0", "bool", Option.INTERNAL, False,
           "True if SIGINT has been received."),

    Option("Cron-Enabled", "1", "bool", Option.INTERNAL, False,
           "True if cron command is enabled; if False, cron is silently ignored."),

    Option("Home", "", "string", Option.INTERNAL, False, 
           "User's home directory."),

    Option("Cron", "0", "bool", Option.INTERNAL, False,
           "True if we running from the cron command."),


]

def printOptions(cat):

    for opt in sorted(options, key=lambda o: o.name):

        if opt.category != cat:
            continue

        default = ""

        if not opt.type:
            print >>sys.stderr, "no type given for", opt.name

        if opt.default and opt.type == "string":
            opt.default = '"%s"' % opt.default

        if not opt.default and opt.type == "string":
            opt.default = "_empty_"      
			
        if opt.default:
            default = ", default %s" % opt.default

        default = default.replace("{", "\\{")
        description = opt.description.replace("{", "\\{")    

        print "[[opt_%s]] *%s* (%s%s)::\n%s" % (opt.name, opt.name, opt.type, default, description)


if __name__ == '__main__':

    print "// Automatically generated. Do not edit."
    print
    print "User Options"
    print "~~~~~~~~~~~~"

    printOptions(Option.USER)

    print
    print "Internal Options"
    print "~~~~~~~~~~~~~~~~"
    print

    printOptions(Option.AUTOMATIC)
