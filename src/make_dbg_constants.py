# Build the DebugCmdConstants.h and DebugCmdInfoConstants.cc files from the
# DebugCmdInfoConstants.in file.
#
# We do this via a script rather than maintaining them directly because
# the struct is a little complicated, so has to be initialized from code,
# plus we want to make adding new constants somewhat less painful.
#
# The input filename should be supplied as an argument.
#
# DebugCmds are printed to DebugCmdConstants.h
# DebugCmdInfos are printed to DebugCmdInfoConstants.cc
#
# The input format is:
#
#	cmd: [DebugCmd]
#	names: [space delimited names of cmd]
#	resume: ['true' or 'false': should execution resume after this command?]
#	help: [some help text]
#
# Blank lines are skipped.
# Comments should start with // and should be on a line by themselves.

import sys

inputfile = sys.argv[1]

init_tmpl = '''
   {
      DebugCmdInfo* info;
      %(name_init)s
      info = new DebugCmdInfo (%(cmd)s, names, %(num_names)s, %(resume)s, "%(help)s",
                               %(repeatable)s);
      g_DebugCmdInfos.push_back(info);
   }
'''

enum_str = '''
//
// This file was automatically generated from %s
// DO NOT EDIT.
//
enum DebugCmd {
''' % inputfile

init_str = '''
//
// This file was automatically generated from %s
// DO NOT EDIT.
//

#include "util.h"
void init_global_dbg_constants () {
''' % inputfile

def outputrecord():
    global init_str, enum_str

    dbginfo["name_init"] = "const char * const names[] = {\n\t%s\n      };\n" % ",\n\t".join(dbginfo["names"])

    dbginfo["num_names"] = len(dbginfo["names"])

    # substitute into template
    init_str += init_tmpl % dbginfo

    enum_str += "\t%s,\n" % dbginfo["cmd"]

def initdbginfo():
    return {"cmd": "", "name_init": "", "num_names": 0, "names": [],
            "resume": "false", "help": "", "repeatable": "false"}

dbginfo = initdbginfo()

inputf = open(inputfile, "r")
for line in inputf:
    line = line.strip()
    if not line or line.startswith("//"):	# skip empty lines and comments
        continue

    fields = line.split(":", 1)
    if len(fields) != 2:
        raise RuntimeError("Error in debug constant file on line: %s" % line)

    f1, f2 = fields
    f2 = f2.strip()

    if f1 == "cmd":
        if dbginfo[f1]:  # output the previous record
            outputrecord()
            dbginfo = initdbginfo()

        dbginfo[f1] = f2
    elif f1 == "names":
        # put quotes around the strings
        dbginfo[f1] = [ '"%s"' % n for n in f2.split() ]
    elif f1 == "help":
        dbginfo[f1] = f2.replace('"', '\\"') # escape quotation marks
    elif f1 in ("resume", "repeatable"):
        dbginfo[f1] = f2
    else:
        raise RuntimeError("Unknown command: %s" % line)

# output the last record
outputrecord()

init_str += "   \n}\n"
enum_str += "   dcLast\n};\n"

debugcmds = open("DebugCmdConstants.h", "w")
debugcmds.write(enum_str)
debugcmds.close()

debugcmdinfos = open("DebugCmdInfoConstants.cc", "w")
debugcmdinfos.write(init_str)
debugcmdinfos.close()
