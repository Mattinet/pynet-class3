#!/usr/bin/env python

import snmp_helper
import email_helper
import time
from datetime import datetime, timedelta

class device(object):
	def __init__(self, ip, port):
		'''defines the router object'''
		self.a_device = (ip, port)

	def query_get(self, oid):
		'''make a snmp-get using the specific oid and return the output'''
		snmp_data = snmp_helper.snmp_get_oid(self.a_device, oid, display_errors=True)
		return snmp_data

	def extract(self, oid):
		snmp_data = snmp_helper.snmp_extract(oid)
		return snmp_data

	def get_sysinfo(self):
		# Uptime when running config last changed
		ccmHistoryRunningLastChanged = '1.3.6.1.4.1.9.9.43.1.1.1.0'   

		# Uptime when running config last saved (note any 'write' constitutes a save)    
		ccmHistoryRunningLastSaved = '1.3.6.1.4.1.9.9.43.1.1.2.0'   

		# Uptime when startup config last saved   
		ccmHistoryStartupLastChanged = '1.3.6.1.4.1.9.9.43.1.1.3.0'

		#system uptime
		sysUptime = '1.3.6.1.2.1.1.3.0'

		oidRunningLastChanged = snmp_helper.snmp_get_oid_v3(self.a_device, self.snmp_user, ccmHistoryRunningLastChanged, display_errors=True)
		self.RunningLastChanged = snmp_helper.snmp_extract(oidRunningLastChanged)
		oidRunningLastSaved = snmp_helper.snmp_get_oid_v3(self.a_device, self.snmp_user, ccmHistoryRunningLastSaved, display_errors=True)
		self.RunningLastSaved = snmp_helper.snmp_extract(oidRunningLastSaved)
		oidStartupLastChanged = snmp_helper.snmp_get_oid_v3(self.a_device, self.snmp_user, ccmHistoryStartupLastChanged, display_errors=True)
		self.StartupLastChanged = snmp_helper.snmp_extract(oidStartupLastChanged)
		sysuptime_oid = snmp_helper.snmp_get_oid_v3(self.a_device, self.snmp_user, sysUptime, display_errors=True)
		self.sysuptime = snmp_helper.snmp_extract(sysuptime_oid)
		sysname_oid = snmp_helper.snmp_get_oid_v3(self.a_device, self.snmp_user, '.1.3.6.1.2.1.1.5.0', display_errors=True)
		self.sysName = snmp_helper.snmp_extract(sysname_oid)
		print "\n" + self.sysName
		print "uptime %s" % self.sysuptime
		self.RunningLastChangedDelta = int(self.sysuptime) - int(self.RunningLastChanged)
		self.RunningLastSavedDelta = int(self.sysuptime) - int(self.RunningLastSaved)
		self.StartupLastChangedDelta = int(self.sysuptime) - int(self.StartupLastChanged)
		print "running changed %s delta %i minutes" % (self.RunningLastChanged, self.RunningLastChangedDelta/6000)
		print "running saved %s delta %i minutes" % (self.RunningLastSaved, self.RunningLastSavedDelta/6000)
		print "startup changed %s delta %i minutes" % (self.StartupLastChanged, self.StartupLastChangedDelta/6000)
def send_mail(recipient, subject, message, sender):
    '''
    Simple function to help simplify sending SMTP email

    Assumes a mailserver is available on localhost
    '''

    import smtplib
    from email.mime.text import MIMEText

    message = MIMEText(message)
    message['Subject'] = subject
    message['From'] = sender
    message['To'] = recipient

    # Create SMTP connection object to localhost
    smtp_conn = smtplib.SMTP('localhost')

    # Send the email
    smtp_conn.sendmail(sender, recipient, message.as_string())

    # Close SMTP connection

    smtp_conn.quit()

    return True

def main():
	'''Connect to rtr1 and rtr2 and print snmp stuff'''
	snmp_username = 'pysnmp'
	snmp_auth_key = 'galileo1'
	snmp_encrypt_key = 'galileo1'
	snmp_user = (snmp_username, snmp_auth_key, snmp_encrypt_key)

	#email details
	sender = 'Pynet-class@twb-tech.com'
	recipient = 'matti.a.nikula@gmail.com'
	subject = 'Test message'
	message = ''

	rtr1 = device('50.76.53.27','7961')
	rtr1.snmp_user = snmp_user
	rtr2 = device('50.76.53.27','8061')
	rtr2.snmp_user = snmp_user
#	rtr1.oid = rtr1.query_get('.1.3.6.1.2.1.1.1.0')
#	rtr1.sysDescr = rtr1.extract(rtr1.oid)
#	rtr1.oid = rtr1.query_get('.1.3.6.1.2.1.1.5.0')
#	rtr1.sysName = rtr1.extract(rtr1.oid)
	
#	print rtr1.oid
#	print rtr1

	while True:
		rtr1.get_sysinfo()
		rtr2.get_sysinfo()
		if (rtr1.RunningLastChangedDelta/6000 < 5):
			print rtr1.sysName + " changed at %s" % datetime.now()
			message += rtr1.sysName + " changed at %s \n" % (datetime.now() - - timedelta(seconds=rtr1.RunningLastChangedDelta/100))
		elif rtr2.RunningLastChangedDelta/6000 < 5:
			print rtr2.RunningLastChangedDelta
			print rtr2.sysName + " changed at %s" % (datetime.now() - timedelta(seconds=rtr2.RunningLastChangedDelta/100))
			print "now is %s" % datetime.now()
                        message += rtr2.sysName + " changed at %s \n" % (datetime.now() - timedelta(seconds=rtr2.RunningLastChangedDelta/100))
		if len(message) > 0:
			email_helper.send_mail(recipient, subject, message, sender)
		message = ""
		time.sleep(300)
if __name__ == "__main__":
	main()

