#!/usr/bin/python
#
# github.com/emsearcy/bacula-scripts/wormvolmgmt.py
#
# Bacula integration script for NetApp SnapLock compliance software.
# Commits used volumes to SnapLock WORM state, matching Bacula retentions.
#
# Authors:
# Eric Searcy <emsearcy@gmail.com>
#
# "NetApp" and "SnapLock" are trademarks of NetApp, Inc., registered in the
# United States and/or other countries.
#
# "wormvolmgmt.py" is an independent work and has not been authorized,
# sponsored, or otherwise approved by NetApp, Inc.

from datetime import datetime, timedelta
import locale
import os
import re
import subprocess
import sys

def main():
   # TODO: device should be runtime option
   device = '/srv/bacula/worm0/'

   try:
      fullmedia = getmedia('FullWorm')
      diffmedia = getmedia('DiffWorm')
      incrmedia = getmedia('IncrWorm')
      for vol in fullmedia + diffmedia + incrmedia:
         # Commit to WORM state
         if (
               # Statuses that mean we won't write again
               (
                  vol['volstatus'] == 'Used' or
                  vol['volstatus'] == 'Read-Only' or
                  (
                     # Unwritten "Error" can be left writeable for purge
                     vol['volstatus'] == 'Error' and
                     vol['lastwritten'] != None
                  )
               ) and
               # We will be able to chmod the file
               os.access(device + vol['volumename'], os.W_OK)
            ):
            print "[%s] Committing %s volume %s to WORM..." % (datetime.now(), vol['volstatus'], vol['volumename'])
            committoworm(vol, device)

         # Delete past-retention volumes
         if (
               # Statuses to delete
               vol['volstatus'] == 'Purged' or
               (
                  vol['volstatus'] == 'Error' and
                  (
                     # "Error" volumes won't be auto-purged, so we can estimate
                     # retention time, unless it was never written to
                     vol['lastwritten'] == None or
                     vol['lastwritten'] + timedelta(seconds=vol['volretention']) < datetime.now()
                  )
               )
            ):
            print "[%s] Destroying %s volume %s..." % (datetime.now(), vol['volstatus'], vol['volumename'])
            delwormfile(vol, device)

   except OSError as e:
      # Popen, unlink
      sys.stderr.write("%s process error (%s): %s\n" % (sys.argv[0], e.filename, e.errstr))
   except BConsoleError as e:
      # bconsole interation errors
      sys.stderr.write("%s failure: %s\n" % (sys.argv[0], e))
      # debug
      sys.stderr.write("bconsole said:\n")
      sys.stderr.write(e.output)

def committoworm(volume, device):
   if not (volume['volstatus'] == 'Used' or volume['volstatus'] == 'Read-Only' or volume['volstatus'] == 'Error'):
      # Ensure volume is in a state where it will not be written further
      newstate = 'Used'

      bc = subprocess.Popen(['/usr/sbin/bconsole', '-n'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
      cmd = "update volume=%s VolStatus=%s" % (volume['volumename'], newstate)
      (bc_out, bc_err) = bc.communicate(cmd)

      if bc.returncode != 0:
         raise BConsoleError("bconsole exited %s" % bc.returncode, cmd, bc_out)
   
      parseout = bc_out.splitlines()
      if not (re.match('New Volume status is: %s$' % newstate, parseout[-1])):
         raise BConsoleError('bconsole command error', cmd, bc_out)


   # Generate NetApp SnapLock protection age to match Bacula retention
   epoch = datetime(1970, 1, 1)
   atime_delta = volume['lastwritten'] + timedelta(seconds=volume['volretention']) - epoch
   atime = atime_delta.days * 86400 + atime_delta.seconds

   volfile = device + volume['volumename']

   try:
      # Commit to WORM by setting future access time, remove write perms
      os.utime(volfile, (atime, os.stat(volfile).st_mtime))
      os.chmod(device + volume['volumename'], 0440)
   except IOError as e:
      print "[%s] Warning: WORM commit failed for volume %s" % (datetime.now(), volume['volumename'])

def delwormfile(volume, device):
      volfile = device + volume['volumename']
      if not os.access(volfile, os.F_OK):
         # No file, just remove from Bacula
         deletevol(volume['volumename'])
      else:
         volstat = os.stat(volfile)
         if datetime.fromtimestamp(volstat.st_atime) < datetime.now():
            # Remove from Bacula
            deletevol(volume['volumename'])
            # Remove from file system
            os.unlink(volfile)
         else:
            # Don't try to remove a volume still protected by SnapLock
            print "[%s] Warning: skipping future-atime volume %s" % (datetime.now(), volume['volumename'])

def getmedia(pool):
   bc = subprocess.Popen(['/usr/sbin/bconsole', '-n'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
   cmd = "llist media pool=%s" % pool
   (bc_out, bc_err) = bc.communicate(cmd)

   if bc.returncode != 0:
      raise BConsoleError("bconsole exited %s" % bc.returncode, cmd, bc_out)

   # Attributes for each media instance are seperated by newlines, with two
   # newlines seperating media instances from each other
   result = []
   i = 0
   for entry in bc_out.split("\n\n"):
      for attribute in entry.splitlines():
         if re.match('.*: ERR=', attribute):
            raise BConsoleError('bconsole command error', cmd, attribute)

         attribute = attribute.lstrip()
         # Parse if we already started parsing or the key is mediaid
         if len(result) == i+1 or attribute.lower()[:9] == 'mediaid: ':
            # Parse the attribute name and value
            sep = attribute.find(': ')
            if sep == -1:
               raise BConsoleError('bconsole parse error', cmd, attribute)
            # Save the attribute name (array key) as lowercase for
            # compatibility across Bacula versions
            key = attribute[:sep].lower()
            value = attribute[sep+2:]

            # Add a result if this is a new mediaid
            if len(result) <= i:
               result.append({})

            # Additional handling of special values
            if re.match('[0-9]{1,3}(,[0-9]{3})*\.[0-9]+$', value):
               value = locale.atof(value)
            elif re.match('[0-9]{1,3}(,[0-9]{3})*$', value):
               value = locale.atoi(value)
            elif value == '0000-00-00 00:00:00':
               value = None
            elif value == '':
               value = None
            elif re.match('[0-9]{4}-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]', value):
               value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')

            # Save this attribute into this result
            result[i][key] = value
      # Next result slot
      i += 1

   return result

def deletevol(volume):
   bc = subprocess.Popen(['/usr/sbin/bconsole', '-n'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
   cmd = "delete volume=%s yes" % volume
   (bc_out, bc_err) = bc.communicate(cmd)

   if bc.returncode != 0:
      raise BConsoleError("bconsole exited %s" % bc.returncode, cmd, bc_out)

   parseout = bc_out.splitlines()
   if not (re.match('This command will delete volume ', parseout[-2]) and re.match('and all Jobs saved on that volume from the ', parseout[-1])):
      raise BConsoleError('bconsole command error', cmd, bc_out)

   return True

class BConsoleError(Exception):
   def __init__(self, value):
      self.value = value
      self.command = '?'
      self.output = None
   def __init__(self, value, command, output):
      self.value = value
      self.command = command
      self.output = output
   def __str__(self):
      return "<%s> %s" % (str(self.command), str(self.value))

if __name__ == '__main__':
   locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
   sys.stdout = open('/var/spool/bacula/wormstatus.log', 'a')
   main()

# vim: ai et sw=3 ts=3
