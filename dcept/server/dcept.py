#!/usr/bin/python

# DCEPT
# James Bettke
# Dell SecureWorks 2016

import logging
from logging import Logger
import ConfigParser
from ConfigReader import config
from ConfigReader import ConfigError

import GenerationServer
from Cracker import cracker
import alert

import os
import sys
import socket
import pyshark
import pyiface

import urllib
import urllib2

# Globals
genServer = None

class DceptError(Exception):
    def __init__(self, message=""):
        Exception.__init__(self,message)

def kerbsniff(interface, username, domain, realm):
    logging.info("kerbsniff: Looking for %s\%s on %s" % (domain, username, interface))
    
    filtered_cap = pyshark.LiveCapture(interface, bpf_filter='tcp port 88')
    packet_iterator = filtered_cap.sniff_continuously
    
    # Loop infinitely over packets if in continuous mode
    for packet in packet_iterator():

        # Is this packet kerberos?
        kp = None
        reqInfo = None
        encTimestamp = None
        try:
            kp = packet['kerberos']
            # Extract encrypted timestamp for Kerberos Preauthentication packets
            # that conatin honeytoken domain\username
            reqInfo = kerb_handler(kp, packet.ip, domain, username)
            encTimestamp = reqInfo[0]
        except KeyError as e:
            pass

        # Only attempt to decrypt a password or notify master if we find an encrypted timestamp
        if encTimestamp:
            if config.master_node:
                notifyMaster(username, domain, encTimestamp, reqInfo[1])
            else:
                cracker.enqueueJob(username, domain, encTimestamp, reqInfo[1], passwordHit)

def notifyMaster(username, domain, encTimestamp, reqInfo):
    url = 'http://%s/notify' % (config.master_node)
    values = {"u": username, "d": domain, "t": encTimestamp, "h": reqInfo[0], "s": reqInfo[1]}
    data = urllib.urlencode(values)

    try:
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req, timeout=30)
    except (urllib2.URLError, socket.timeout) as e:
        message = "DCEPT slave Failed to communicate with master node '%s'" % (config.master_node)
        logging.error(message)
        alert.sendAlert(message)
        return False
    return True

def passwordHit(genServer, password, reqInfo):
    if password:
        record = genServer.findPass(password)
        # [RED ALERT] Honeytoken 'XDPXKue3K8' for TEST-HONEYTOKEN.COM\Administrator was stolen from ip2(10.65.189.18) on 2019-07-10 03:07:03.304525 attempted to use in ip2(10.65.189.18)
        message = "[RED ALERT] Honeytoken '%s' for %s\\%s, stolen from %s(%s) on %s, was attempted to use in %s(%s)" % \
            (record[5], record[1], record[2], record[4], record[3], record[0].split(".")[0], reqInfo[0], reqInfo[1])
        logging.critical(message)
        alert.sendAlert(message)

# Parse Kerberos packet and return the encrypted timestamp only if we detected 
# honeytoken usage (honey domain\username)
def kerb_handler(kp, kpip, domain, username):
    reqInfo = [None, None]
    encTimestamp = None

    # We are looking for kerberos packets of message type: AS-REQ (10)
    # kp.pretty_print() 
    if kp.msg_type == "10":

        # Depending on the version of TShark installed, the krb 
        # dissector will display the username field under a different name
        reqInfo = [kp.addr_nb, kpip.src]
        logging.debug("A kerberos request from %s(%s)" % (reqInfo[0], reqInfo[1]))

        try:
            kerbName = kp.CNameString
        except AttributeError:
            pass

        try:
            kerbName = kp.kerberosstring
        except AttributeError:
            pass

        realm = kp.realm
        logging.debug("kerb-as-req for domain user %s\%s" % (realm, kerbName))

        if kerbName.lower() == username.lower() and realm.lower() == config.realm.lower():
            # Depending on the version of TShark installed, the krb 
            # dissector will display the encrypted field under a different name
            try:
                encTimestamp = kp.pa_enc_timestamp_encrypted.replace(":", "")
            except AttributeError:
                pass

            try:
                encTimestamp = kp.cipher.replace(":", "")
            except AttributeError:
                pass

            logging.debug("PA-ENC-TIMESTAMP: %s", encTimestamp)
        else:
            logging.debug("Ignoring kerb-as-req for '%s\%s'" % (realm, kerbName))

    else:
        logging.debug("Ignoring kerberos packet - Not kerb-as-req")

    return [encTimestamp, reqInfo]

def testInterface(interface):
    try:
        iface = pyiface.Interface(name=interface)
        if iface.flags == iface.flags | pyiface.IFF_UP:
            return True
    except IOError as e:
        if e.errno == 19: # No such device
            logging.info("Bad interface. No such device '%s'" % (interface))
    return False

def main():
    logging.info(" _____   _____ ______ _____ _______ ")
    logging.info("|  __ \ / ____|  ____|  __ |__   __|")
    logging.info("| |  | | |    | |__  | |__) | | |   ")
    logging.info("| |  | | |    |  __| |  ___/  | |   ")
    logging.info("| |__| | |____| |____| |      | |   ")
    logging.info("|_____/ \_____|______|_|      |_|   ")
    logging.info("                                    ")

    # Server roles for multi-server topology
    if not config.master_node:
        logging.info('Server configured as master node')
    else:
        logging.info('Server configured as slave node')

    # Test Connection to master node
    # Sanity check - Check if the interface is up
    if not testInterface(config.interface):
        logging.error("Unable to listen on '%s'. Is the interface up?" % (config.interface))
        raise DceptError()

    logging.info('Starting DCEPT...')

    # Only master node should run the generation server and cracker 
    if not config.master_node: # (Master Node)
        # Spawn and start the password generation server
        try:
            global genServer 
            genServer = GenerationServer.GenerationServer(config.honeytoken_host, config.honeytoken_port)
        except socket.error as e:
            logging.error(e)
            logging.error("Failed to bind honeytoken HTTP server to address %s on port %s" % (config.honeytoken_host, config.honeytoken_port))
            raise DceptError()

        # Initialize the cracker
        cracker.start(genServer)

    else: # (Slave Node)
        # Test sending notifications to the master node
        logging.info("Testing connection to master node '%s'" % (config.master_node))
        if not notifyMaster('u', 'd', 't'):
            raise DceptError()

    # Start the sniffer (Both master and slave)
    try:
        kerbsniff(config.interface, config.honey_username, config.domain, config.realm)
    except pyshark.capture.capture.TSharkCrashException:
        logging.error(message)
        raise DceptError(message)

if __name__ == "__main__":
    try:
        # Setup logging to file for troubleshooting
        logging.basicConfig(
            level    = logging.DEBUG,
            format   = '[%(asctime)s] %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
            datefmt  = '%Y-%m-%d %A %H:%M:%S',         
            filename = '/opt/dcept/var/dcept.log',
            filemode = 'a')

        try:
            # Read the configuration file
            config.load("/opt/dcept/dcept.cfg")
        except (ConfigParser.Error, ConfigError) as e:
            logging.error(e)
            raise DceptError()

        # Define a Handler and set a format which output to console
        console = logging.StreamHandler()
        console.setLevel(config.log_level.upper())
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s %(message)s')
        console.setFormatter(formatter)

        # Create an instance
        logging.getLogger().addHandler(console)

        # Go to the main handler
        main()
    except (KeyboardInterrupt, DceptError):
        logging.info("Shutting down DCEPT...")
