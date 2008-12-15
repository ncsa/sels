# Modified by: SELS Team for use with SELS
# License: This code is distributed under GPL License. (refer http://www.gnu.org/copyleft/gpl.html)
############################################################################################################################
# Copyright (C) 2005 by Stefan Schlott
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software 
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

"""Decrypt the incoming message using the list key

"""

from Mailman import Errors
from Mailman.Logging.Syslog import syslog
from Mailman import mm_cfg
#from Mailman import GPGUtils
from Mailman import Utils
from socket import *
from SELSpath import *
from mailmanlogs import *
import threading
import GnuPGInterface
import os
import string

#
# subject: Unsubscribe userid listname
#
# subject: Join userid listname 
#
# subject: Update listname 
#
def process(mlist, msg, msgdata):   
	syslog('error', 'sels handler' )
	subject = msg.get('subject', 'no subject')
	sender = msg.get_sender()
	if subject:
		wlist = string.split(subject)
		if ((wlist[0] == 'Join' or wlist[0] == 'Unsubscribe' or \
			wlist[0] == 'Create' or wlist[0] == 'LKpubkey')):
			syslog('error', 'handling....' )
			# save message body to the temporay file
			syslog('error', "subject=" + subject )
			syslog('error', msg.get_payload() )
			msgfile =  MAILMAN_LOG_PATH + '/SELS_msg.txt'
			try:
				fp = open(msgfile, 'w')
				fp.write(msg.get_payload())
				fp.close()
			except IOError:
				syslog('error', "Cannot open msgfile file")
			selslog = MAILMAN_LOG_PATH + "/SELS.log"
			cmd = "python %s/bin/SELSProcess.py -s '%s' -f %s >> %s 2>&1 "%(SELSPATH, subject, msgfile, selslog)
			os.system(cmd);
			raise Errors.DiscardMessage
		elif (len(msg.get_payload()) == 0):
			syslog( 'error', "empty message; message was discarded" )
			raise Errors.DiscardMessage
		else:
			plaintext(mlist, msg, msgdata, subject, sender)
			
	else:	
		#Check no subject cases too
		plaintext(mlist, msg, msgdata, subject, sender)

def plaintext(mlist, msg, msgdata, subject, sender):
	#Send the plaintext message to list moderator
	msgstr = str(msg)
	payloadstr = str(msg.get_payload())
	if (msgstr.find('-----BEGIN PGP MESSAGE-----') == -1):
		to = mlist.owner[0]
		add0 = "A message sent by you on list %s was dropped at the server."%(mlist.internal_name())
		add1 = " This SELS list only allows encrypted OR encrypted and signed messages. Additionally SELS only supports"
		add2 = " PGP MIME encryption for HTML messages and encrypted attachments. Please resend."
		add3 = "Dropped Message Subject: "
		msgmod = add0 + add1 + add2 + '\n'+ add3 + subject + '\n'
		msgfile = MAILMAN_LOG_PATH + '/SELS_msg.txt'
		syslog("error","plaintext message on list %s bounced back to user %s"% (mlist.internal_name(),sender))
		try:
			fp = open(msgfile, 'w')
			fp.write(msgmod)
			fp.close()
		except IOError:
			syslog('error', "Cannot open msgfile file")
		selslog = MAILMAN_LOG_PATH + "/SELS.log"
		cmd = "python %s/bin/SELSProcess.py -l %s -u %s -f %s -b >> %s  2>&1"%\
 	               (SELSPATH, mlist.internal_name(),sender, msgfile, selslog)

		os.system(cmd)
		raise Errors.DiscardMessage
	else:
		syslog("error"," Encrypted message is being sent on list %s"% (mlist.internal_name()))


