#!/usr/bin/env python
import re
import os
import sys
import time
import string
import math
import getopt

rawlogs=None
processedlogs=None

# invoke a sed script to remove the last byte from the ips 
def maskit(file):
    cmd = "sed -f mask-addr.sed %s > %s.masked" % (file,file)
    ret = os.system(cmd)
    if ret != 0:
        print "error with %s" % cmd
    cmd = "rm %s" % file
    ret = os.system(cmd)
    if ret != 0:
        print "error with %s" % cmd
    cmd = "mv %s.masked %s" % (file, file)
    ret = os.system(cmd)
    if ret != 0:
        print "error with %s" % cmd

def get_files(dir, myfilter='.*\.example$', includezero = False):
    """get all '*.example' files"""
    SIZE = 6
    flist=[]
    files = os.listdir(dir)
    test = re.compile(myfilter, re.IGNORECASE)
    files = filter(test.search, files)
    for f in files:
        s = os.stat(dir + '/' + f)[SIZE]
        if s > 0 or includezero:
            flist.append(f)
    return flist

def sort_conn(f):
    # move to new file
    cmd = "mv %s %s.sortme" % (f,f)
    ret = os.system(cmd)
    if ret != 0:
        print "error with %s" % cmd
    # sort it
    cmd = "sort %s.sortme > %s" % (f, f)
    ret = os.system(cmd)
    if ret != 0:
        print "error with %s" % cmd
    # we can allow a one byte difference (probably newline)
    if math.fabs(os.stat(f)[6] - size) >= 2:
        print "Error sizes don't match! %d != %d (%s)" % ( os.stat(f)[6], size, f)
        sys.exit(1)
    # remove old file (now called .sortme)
    cmd = "rm %s" % (f + ".sortme")
    ret = os.system(cmd)
    if ret != 0:
        print "error with %s" % cmd

def move_it(f,fname):
    # move it on over
    cmd = "mv %s %s/%s" % ( f, processedlogs, fname )
    ret = os.system(cmd)
    if ret != 0:
        print "error with %s" % cmd

def usage(msg=None):
    if msg != None:
        print msg
    print """process_bro_logs.py -h -l logsdir -r rawlogsdir"""
    print """    -h             This help message"""
    print """    -l logsdir     Directory where the logs should end up"""
    print """    -r rawlogsdir  Directory where the raw logs reside"""
    sys.exit(1)

####################################################
# This is the start of the script


try:
    options,prog_args = getopt.getopt(sys.argv[1:],'hl:r:')
except getopt.GetoptError, E:
   usage(E)

for opt,val in options:
  if opt == '-l':
      processedlogs = val
  elif opt == '-r':
      rawlogs = val
  else:
      usage()


if rawlogs == None or processedlogs == None:
    usage()

# get to the right place
os.chdir(rawlogs)

# look for logs that have been split
fl1 = get_files(rawlogs, 
    myfilter='^(\w+)\.\w+\.(\d{2})-(\d{2})-(\d{2})[-_](\d{2})[:.](\d{2})[:.](\d{2})\.[0-9]+\.[0-9]+\.[0-9]+$')

for f in fl1:
    print "Working on split file: ", f
    # grab times before we mess with it
    size,atime,mtime,ctime = os.stat(f)[6:10]
    type,host = string.split(f,'.')[0:2]

    broend = string.split(f, ".")[-2:-1][0]

    # only sort conn files
    if f[:4] == 'conn':
        sort_conn(f)

    cmd = 'sync'
    ret = os.system(cmd)
    #grab the 2nd timestamp
    cmd = 'head -2 %s | tail -1' % f
    if ret != 0:
        print "error with %s" % cmd

    fo=os.popen(cmd)
    buf = fo.read()
    fo.close()
    brostart = buf.split('.')[:1]

    # sanity check
    if brostart[0] < 1090000000 or len(brostart[0]) != 10:
        print "File error! Stopping"
        sys.exit(1)

    # construct new filenaem
    fname = "%s.%s.%s-%s" % (type,host,brostart[0],broend)

    # does a file with name already exist?
    if os.access("%s/%s" % (processedlogs, fname), os.F_OK):
        print "File %s already exists" % fname
        print "Skipping %s" % fname
        continue

    move_it(f,fname)
    os.utime("%s/%s" % (processedlogs,fname), (mtime,mtime))
    print "Done with %s" % f
    # lets not run too fast
    time.sleep(3)
    continue

# look for files that haven't been split
fl2 = get_files(rawlogs, 
    myfilter='^(\w+)\.\w+\.(\d{2})-(\d{2})-(\d{2})[-_](\d{2})[:.](\d{2})[:.](\d{2})$')

for f in fl2:
    print "Working on file: ", f
    # grab times before we mess with it
    size,atime,mtime,ctime = os.stat(f)[6:10]
    type,host = string.split(f,'.')[0:2]

    brostart = string.join(string.split(f, ".", 2)[2:])
    foo = list(time.strptime(brostart, '%Y-%m-%d_%H.%M.%S'))

    # toggle guessing of daylight savings, grrrr
    foo[-1] = -1
    bs = time.mktime(foo)
    fname = "%s.%s.%d-%s" % (type,host,bs,mtime)

    if os.access("%s/%s" % (processedlogs,fname), os.F_OK):
        print "File %s already exists, skipping" % fname
        continue

    # sort conn files
    if f[:4] == 'conn':
        sort_conn(f)

    move_it(f, fname)
    os.utime("%s/%s" % (processedlogs,fname), (mtime,mtime))
    print "Done with %s (%s)" % (fname,f)
    # lets not overrun things
    time.sleep(3)
    continue
