#! /usr/bin/env python
# 
# Tests persistence.
#
# $Id: istate.py,v 1.1.2.4 2005/10/11 22:31:42 sommer Exp $

import time
import os
import os.path
import optparse
import sys
import subprocess

import tests

optparser = optparse.OptionParser( usage = "%prog [options]", version = "0.1" )
optparser.add_option( "-s", "--show-diff", action = "store_true", dest = "showdiff", 
                    default = False, help = "show diffs of mismatches" )
optparser.add_option( "-b", "--new-base", action = "store_true", dest = "newbase", 
                    default = False, help = "create new baseline" )
optparser.add_option( "-d", "--debug", action = "store_true", dest = "debug", 
                    default = False, help = "enable debug output" )
optparser.add_option( "-t", "--set", action = "store", type = "string", dest = "set", 
                    default = None, help = "only do given test set" )

                    
( tests.Options, args ) = optparser.parse_args()

if len(args) != 0:
    optparser.error( "Wrong number of arguments" )

##########################################    
# Write persistent data and read it back.
##########################################

if tests.testSet("persistence"):

    tests.spawnBro("persistence-write", 
               ["-r", os.path.join(tests.Traces, "empty.trace"), 
                os.path.join(tests.Scripts, "vars-init.bro"),
                os.path.join(tests.Scripts, "vars-print.bro")])
    tests.waitProc("persistence-write")
    tests.finishTest("persistence-write", ["stdout.log", "stderr.log", "vars.log"])

    tests.spawnBro("persistence-read", 
               [os.path.join(tests.Scripts, "vars-declare.bro"),
                os.path.join(tests.Scripts, "vars-print.bro")], 
                copy=[os.path.join(tests.workDir("persistence-write"), ".state")])
    tests.waitProc("persistence-read")
    tests.finishTest("persistence-read", ["stdout.log", "stderr.log", "vars.log"])

    tests.compareFiles("persistence-write", "persistence-read", ["vars.log"])

##########################################    
# Exchange events (clear-text).
#
# The used trace contains two connections separated by a silence of a 
# couple of seconds. We start the processes so that the events for the 
# *second* one (which is a full HTTP connection) are exchanged.
##########################################    

if tests.testSet("events"):

    tests.spawnBro("events-send", 
               ["-r", os.path.join(tests.Scripts, os.path.join(tests.Traces, "web.trace")), 
                "--pseudo-realtime", 
                "-C",
               os.path.join(tests.Scripts, "events-send.bro")])
    time.sleep(2)
    tests.spawnBro("events-rcv", 
               [os.path.join(tests.Scripts, "events-rcv.bro")])
    tests.waitProc("events-send")
    tests.killProc("events-rcv")
    tests.finishTest("events-send", ["stdout.log", "stderr.log", "http.log", "conn.log"], ignoreTime=True)
    tests.finishTest("events-rcv", ["stdout.log", "stderr.log", "http.log", "conn.log"], ignoreTime=True)

    tests.spawnBro("events-display", 
               ["-x", os.path.join(tests.workDir("events-rcv"), "events.bst")])
    tests.waitProc("events-display")
    tests.finishTest("events-display", ["stdout.log"], ignoreTime=True, sort=True, delete=['127.0.0.1:[0-9]*',"Event.*remote_.*"])

    tests.compareFiles("events-send", "events-rcv", ["http.log"], ignoreTime=True, ignoreSessionID=True)

##########################################    
# Exchange synchronized state
##########################################    

if tests.testSet("sync"):

    tests.spawnBro("sync-send", 
               [os.path.join(tests.Scripts, "vars-sync-send.bro")])
    tests.spawnBro("sync-rcv", 
               [os.path.join(tests.Scripts, "vars-sync-rcv.bro")])
    tests.waitProc("sync-send")
    time.sleep(1)
    tests.killProc("sync-rcv")
    tests.finishTest("sync-send", ["stdout.log", "stderr.log", "vars.log"], ignoreTime=True)
    tests.finishTest("sync-rcv", ["stdout.log", "stderr.log", "vars.log", "remote.log"], ignoreTime=True, delete=["pid.*pid.*", "temporarily unavailable \\[..\\]"])

    tests.compareFiles("sync-send", "sync-rcv", ["vars.log"], ignoreTime=True)

# Old version    
#    tests.spawnBro("sync-send", 
#               ["-r", os.path.join(tests.Scripts, os.path.join(tests.Traces, "web.trace")), 
#       	        "--pseudo-realtime", 
#                "-C",
#               os.path.join(tests.Scripts, "vars-sync-send.bro")])

##########################################
# Test Broccoli with bro-ping
##########################################


if tests.testSet("broccoli"):

    broctest = os.path.join(tests.Bro, "aux/broccoli/test")    
    broclib = os.path.join(tests.Bro, "aux/broccoli/src/.libs")
    broping = os.path.join(broctest, "broping")

    brocpy = os.path.join(tests.Bro, "aux/broccoli/bindings/python")    

    broccoli = True
    
    # Test if Broccoli was compiled.
    if not os.path.exists(broping):
        print "    Broccoli was not compiled, skipping tests."
        broccoli = False
        
    # Test if this is a IPv6 Bro. 
    if broccoli:
        v6 = subprocess.call(["grep", "-q", "#define BROv6", os.path.join(tests.Bro, "config.h")])
        if v6 == 0:
            print "    Bro built with IPv6 support not compatible with Broccoli, skipping tests."
            broccoli = False

    if broccoli:
        tests.spawnBro("bro-ping", [os.path.join(broctest, "broping-record.bro")])
        time.sleep(1)
        tests.spawnProc("broccoli-ping", 
                        [broping, 
                        "-r", 
                        "-c", "5", 
                        "127.0.0.1"])
        tests.waitProc("broccoli-ping")
        tests.killProc("bro-ping")
    
        tests.finishTest("bro-ping", ["stdout.log", "stderr.log", "remote.log"], 
                         ignoreTime=True, delete=["127.0.0.1:[0-9]*", "pid.*pid.*", 
                         ".*Resource temporarily unavailable.*", ".*connection closed.*", 
                         ".*peer disconnected.*"])
        tests.finishTest("broccoli-ping", ["stdout.log", "stderr.log"],
                         delete=["time=.* s$"])
                         
        # Test if Python binding are installed.
        sopath = subprocess.Popen(["find", brocpy, "-name", "_broccoli_intern.so"], stdout=subprocess.PIPE).communicate()[0]
        if sopath != "":

            os.environ["LD_LIBRARY_PATH"] = broclib
            os.environ["DYLD_LIBRARY_PATH"] = broclib
            os.environ["PYTHONPATH"] = os.path.dirname(sopath)
            
            tests.spawnBro("python-bro", [os.path.join(brocpy, "tests/test.bro")])
            time.sleep(1)
            tests.spawnProc("python-script", [os.path.join(brocpy, "tests/test.py")])
            tests.waitProc("python-script")
            tests.killProc("python-bro")
            tests.finishTest("python-bro", ["stdout.log"], ignoreTime=True)
            tests.finishTest("python-script", ["stdout.log"], ignoreTime=True, delete=["0x[^>]*", ".[0-9]{2}"])
        else:
            print "    Python bindings not built, skipping test."
            print "       (To build: cd %s && python setup.py build)" % brocpy
                         

    
