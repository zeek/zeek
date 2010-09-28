#! /usr/bin/env python
#
# $Id: util.py 6956 2009-12-14 22:01:17Z robin $

import os
import sys
import socket
import imp
import re
import time
import tempfile
import signal
import StringIO
import tty
import termios
import select
import curses
import atexit

import config
import execute

def fmttime(t):
    return time.strftime(config.Config.timefmt, time.localtime(float(t)))

Buffer = None

def bufferOutput():
    global Buffer
    Buffer = StringIO.StringIO()

def getBufferedOutput():
    global Buffer
    buffer = Buffer.getvalue()
    Buffer.close()
    Buffer = None
    return buffer

def output(msg = "", nl = True):

    debug(1, "[output] %s %s" % (msg, (not nl) and "..." or ""))

    if Buffer:
        out = Buffer
    else:
        out = sys.stderr

    out.write(msg)
    if nl:
        out.write("\n")

def error(msg):
    output("error: %s" % msg)
    sys.exit(1)

def warn(msg):
    output("warning: %s" % msg)

DebugOut = None    

def debug(msglevel, msg):
    global DebugOut

    try:
        level = int(config.Config.debug)
    except ValueError:
        level = 0

    if level < msglevel:
        return

    if not DebugOut:
        try:
            DebugOut = open(config.Config.debuglog, "a")
        except IOError:
            # During the initial install, tmpdir hasn't been setup yet. So we
            # fall back to current dir.
            DebugOut = open("debug.log", "a")

    print >>DebugOut, time.strftime(config.Config.timefmt, time.localtime(time.time())), msg
    DebugOut.flush()

def sendMail(subject, body):
    cmd = "%s '%s'" % (os.path.join(config.Config.scriptsdir, "send-mail"), subject)
    (success, output) = execute.captureCmd(cmd, "", body)
    if not success:
        warn("cannot send mail")

lockCount = 0        

def _breakLock():
    try:
        # Check whether lock is stale.
        pid = open(config.Config.lockfile, "r").readline().strip()
        (success, output) = execute.runHelper(config.Config.manager(), "check-pid", args=[pid])
        if success:
            # Process still exissts.
            return False

        # Break lock.
        warn("removing stale lock")
        os.unlink(config.Config.lockfile)
        return True

    except IOError:
        return False

def _aquireLock():
    if not config.Config.manager() or config.Installing:
        # Initial install.
        return True

    pid = str(os.getpid())
    tmpfile = config.Config.lockfile + "." + pid

    try:
        try:
            # This should be NFS-safe.
            f = open(tmpfile, "w")
            print >>f, pid
            f.close()

            n = os.stat(tmpfile)[3]
            os.link(tmpfile, config.Config.lockfile)
            m = os.stat(tmpfile)[3]

            if n == m-1:
                return True

            # File is locked.
            if _breakLock():
                return _aquireLock()

        except OSError, e:
            # File is already locked.
            if _breakLock():
                return _aquireLock()

        except IOError, e:
            if not config.Config.installing():
                error("cannot aquire lock: %s" % e)
                return False
            else:
                # The spool directory may not exist yet so we 
                # silently ignore the failed lock.
                return True

    finally:
        try:
            os.unlink(tmpfile)
        except OSError:
            pass
        except IOError: 
            pass

    return False

def _releaseLock():
    try:
        os.unlink(config.Config.lockfile)
    except OSError, e:
        if not config.Config.installing():
            warn("cannot remove lock file: %s" % e)

def lock():
    global lockCount

    if lockCount > 0:
        # Already locked.
        lockCount += 1
        return True

    if not _aquireLock():
        
        if config.Config.cron == "1":
            do_output = 0
        else:
            do_output = 2
            
        if do_ouput:
            output("waiting for lock ...", nl=False)

        count = 0
        while not _aquireLock():
            if do_output:
                output(".", nl=False)
            time.sleep(1)

            count += 1
            if count > 30:
                output("cannot get lock") # always output this one.
                return False

        if do_output:
            output(" ok")

    lockCount = 1
    return True

def unlock():
    global lockCount

    if lockCount == 0:
        error("mismatched lock/unlock")

    if lockCount > 1:
        # Still locked.
        lockCount -= 1
        return

    _releaseLock()

    lockCount = 0

# Keyboard interrupt handler.
def sigIntHandler(signum, frame):
    config.Config.config["sigint"] = "1" 

def enableSignals():
    signal.signal(signal.SIGINT, sigIntHandler)

def disableSignals():
    signal.signal(signal.SIGINT, signal.SIG_IGN)


# Curses functions

_Stdscr = None

def _finishCurses():
    curses.nocbreak(); 
    curses.echo()
    curses.endwin()

def _initCurses():
    global _Stdscr
    atexit.register(_finishCurses)
    _Stdscr = curses.initscr()

def enterCurses():    
    if not _Stdscr:
        _initCurses()

    curses.cbreak()
    curses.noecho()
    _Stdscr.nodelay(1)
    
    signal.signal(signal.SIGWINCH, signal.SIG_IGN)

def leaveCurses():
    curses.reset_shell_mode()
    signal.signal(signal.SIGWINCH, signal.SIG_DFL)

# Check non-blockingly for a key press and returns it, or return None if no
# key is found. enter/leaveCurses must surround the getc() call.
def getCh():
    ch = _Stdscr.getch()

    if ch < 0:
        return None

    return chr(ch)

def clearScreen():
    if not _Stdscr:
        _initCurses()

    _Stdscr.clear()

def printLines(lines):
    y = 0
    for line in lines.split("\n"):
        try:
            _Stdscr.insnstr(y, 0, line, len(line))
        except:
            pass
        y += 1
        
    try:
        _Stdscr.insnstr(y, 0, "", 0)
    except:
        pass

