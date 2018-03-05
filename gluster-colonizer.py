#!/usr/bin/env python
#*******************************************************************************
#                                                                              *
#  Copyright (c) 2018 Red Hat, Inc. <http://www.redhat.com>                    *
#                                                                              *
#  This file is licensed to you under the GNU General Public License,          *
#  version 3 (GPLv3), as published by the Free Software Foundation             *
#------------------------------------------------------------------------------*
#                                                                              *
# gluster-colnizer.py:  This script initiates a Gluster deployment based on a  *
#                       recipe defined in a set of OEMID files.                *
#                                                                              *
# Usage:                $ gluster-colonizer.py -f <OEMID FILE>                 *
#                                                                              *
# Authors:              Dustin Black <dustin@redhat.com>                       *
#                         https://github.com/dustinblack                       *
#                       Christopher Blum                                       *
#                         https://github.com/zeichenanonym                     *
#                                                                              *
# Maintainer:           Dustin Black <dustin@redhat.com>                       *
#                                                                              *
#*******************************************************************************

import argparse
from argparse import RawTextHelpFormatter
import json
import logging
import netaddr
import pprint
import re
import string
import socket
import sys
import time
import urllib2
import yaml
from subprocess import *
from netaddr import *
import os
import errno
import shlex
import signal
from termios import tcflush, TCIOFLUSH
import math
import getpass, crypt, random

pp = pprint.PrettyPrinter(indent=2)

# Get command arguments
parser = argparse.ArgumentParser(
    description='Setup Gluster using the colonizer deployment system',
    formatter_class=RawTextHelpFormatter)
parser.add_argument(
    '-f',
    metavar='--file',
    dest='oem_id_file',
    type=argparse.FileType('r'),
    help='The vendor specific file used to define this setup',
    required=True)
parser.add_argument(
    '-l',
    dest='loglevel',
    choices=['10', '20', '30'],
    help=
    'The desired log level - will be 20 (INFO) by default\nAvailable log levels:\n  10 - DEBUG\n  20 - INFO\n  30 - WARN',
    default=20)
args = parser.parse_args()

# Import OEM ID YAML into a dictionary
oem_id_yaml = args.oem_id_file.read()
args.oem_id_file.close()
oem_id = yaml.load(oem_id_yaml)

g1_path = oem_id['flavor']['g1_path']

# Import branding
branding_file = "%sbranding.yml" % g1_path
try:
    with open(branding_file, 'r') as stream:
        branding = yaml.load(stream)
        brand_distributor = branding['brand']['distributor']
        brand_parent = branding['brand']['parent']
        brand_project = branding['brand']['project']
        brand_short = branding['brand']['short']
        brand_banner = branding['brand']['banner']
# Default branding values
except:
    brand_distributor = "Gluster"
    brand_parent = "Gluster"
    brand_project = "Colonizer"
    brand_short = "Colonizer"
    # banner created with: figlet -f slant "Gluster Colonizer"
    brand_banner = """
   ________           __
  / ____/ /_  _______/ /____  _____
 / / __/ / / / / ___/ __/ _ \/ ___/
/ /_/ / / /_/ (__  ) /_/  __/ /
\____/_/\__,_/____/\__/\___/_/

   ______      __            _
  / ____/___  / /___  ____  (_)___  ___  _____
 / /   / __ \/ / __ \/ __ \/ /_  / / _ \/ ___/
/ /___/ /_/ / / /_/ / / / / / / /_/  __/ /
\____/\____/_/\____/_/ /_/_/ /___/\___/_/"""

# Configure random filename sampling
rand_filename_sample = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
rand_filename_len = 8

# Ansible configuration
peerInventory = "/var/tmp/peerInventory.ansible-" + "".join(
    random.sample(rand_filename_sample, rand_filename_len))
ansible_ssh_key = "/home/ansible/.ssh/id_rsa"

# Performance test files
perf_jobfile = "/var/tmp/g1-perf-jobfile.fio-" + "".join(
    random.sample(rand_filename_sample, rand_filename_len))
perf_server_list = "/var/tmp/g1-perf-server.list-" + "".join(
    random.sample(rand_filename_sample, rand_filename_len))
perf_output = "/root/g1-perf-results.out"

# Set maximum number of nodes
# TODO: Move this to OEMID file
nodes_max = 24

# Initialize variables
hostlist = []
desiredNumOfNodes = 0
rhnUser = ""
rhnPassword = ""
storage_subnet = ""
gatewayAddress = ""
dnsServerAddress = []
default_volname = oem_id['flavor']['volname']
consumed_ips = []
readme_file = "/root/colonizer.README.txt"
g1_inventory = ""
playbook_path = g1_path + "ansible/"

# Define management network info
# We are confining to a maximum deployment set of 24 nodes.
# Using a /27 subnet yields a maximum of 30 host IPs.
# TODO: Better user selection of managemenet network config
mgmt_subnet = IPNetwork('172.16.222.64/27')
nm_mgmt_interface = oem_id['flavor']['node']['mgmt_interface']
storage_interface = oem_id['flavor']['node']['storage_interface']

if nm_mgmt_interface.startswith("bond-") or nm_mgmt_interface.startswith(
        "team-"):
    mgmt_interface = nm_mgmt_interface[5:]
else:
    mgmt_interface = nm_mgmt_interface

# Init logging to log to console screen and file
# Create logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
# Create console formatter & handler for logs
consoleHandler = logging.StreamHandler()
consoleHandler.setLevel(int(args.loglevel))
consoleFormatter = logging.Formatter('%(message)s')
consoleHandler.setFormatter(consoleFormatter)
# Create log file formatter & handler for logs
logfile = 'gluster-colonizer.log'
logfileHandler = logging.FileHandler(logfile)
logfileHandler.setLevel(logging.DEBUG)
logfileFormatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s')
logfileHandler.setFormatter(logfileFormatter)
# Add handlers to logger
logger.addHandler(consoleHandler)
logger.addHandler(logfileHandler)


def abortSetup(message=''):
    # This may be called at any time during the setup process to abort
    print "\r\n"
    logger.critical(
        "Something went wrong and the deployment is being aborted.")
    if message != '':
        print "\r\n"
        logger.critical(message)
    print "\r\nPlease wait while services are shut down..."
    stopDhcpService()
    print "\r\n"
    logger.critical("Abort complete. Please reboot all nodes and try again.")
    print "\r\n"
    sys.exit(1)


def user_input(msg):
    # Function to capture raw_input w/ key buffer flush
    tcflush(sys.stdin, TCIOFLUSH)
    keyin = raw_input(msg)
    return keyin


def yes_no(answer, do_return=False, default='yes'):
    # Simple yes/no prompt function
    yes = set(['yes', 'y', 'ye'])
    no = set(['no', 'n'])
    if default is 'no':
        no.add('')
    else:
        yes.add('')
    while True:
        choice = user_input(answer).lower()
        if choice in yes:
            return True
        elif choice in no:
            if do_return:
                return False
            else:
                abortSetup("Deployment cancelled by user.")
        else:
            print "Please enter either 'yes' or 'no'\r\n"

def natural_sort(string):
    convert = lambda text: int(text) if text.isdigit() else text.lower()
    alphanum_key = lambda key: [ convert(c) for c in re.split('([0-9]+)', key) ]
    return sorted(string, key = alphanum_key)


def ipValidator(user_message,
                null_valid=False,
                check_dupes=True,
                check_subnet=True):
    # Function for input and validation of storage network IP addresses
    while True:
        input_string = user_input(user_message)
        if null_valid and not input_string:
            return ''
        try:
            ip = IPAddress(input_string)
        except netaddr.core.AddrFormatError:
            logger.warning("The IP address entered is invalid")
            continue
        if ip not in storage_subnet[1:-1] and check_subnet:
            logger.warning(
                "The IP address is not within the storage network %s" %
                str(storage_subnet))
            continue
        if str(ip) in consumed_ips and check_dupes:
            logger.warning("The IP address is already in use")
            continue
        consumed_ips.append(str(ip))
        break
    return str(ip)


def host_command(command, shell=False):
    # Function to execute system commands
    if shell == True:
        cmd_args = command
    else:
        cmd_args = shlex.split(command)

    logger.debug("Initiating Subprocess: " + command)

    try:
        cmd_proc = Popen(
            cmd_args,
            stdout=PIPE,
            stderr=STDOUT,
            universal_newlines=True,
            shell=shell)

        proc_output, _ = cmd_proc.communicate()

        if proc_output.strip() != "":
            logger.debug("Subprocess output: " + proc_output)
    except (OSError, CalledProcessError) as exception:
        logger.error("Subprocess exception occured: " + str(exception))
        abortSetup("Subprocess failed")

    return proc_output


def run_ansible_playbook(playbook, continue_on_fail=False):
    # Function to run ansible playbooks
    FIFO = "/var/tmp/g1.pipe-" + "".join(
        random.sample(rand_filename_sample, rand_filename_len))
    try:
        os.mkfifo(FIFO)
    except OSError as oe:
        if oe.errno != errno.EEXIST:
            abortSetup("Error creating FIFO")
    watch_ansible = Popen(shlex.split("tail -f " + FIFO))
    playbookCmd = "ansible-playbook -i " + peerInventory + " --ssh-common-args=\'-o StrictHostKeyChecking=no\' --user ansible --sudo --private-key=" + ansible_ssh_key + " --extra-vars=\"{fifo: " + FIFO + "}\" " + playbook
    if int(args.loglevel) == 10:
        playbookCmd = playbookCmd + " -vvv"
    logger.debug("Ansible playbook command: " + playbookCmd)
    returnVal = Popen(
        playbookCmd,
        universal_newlines=True,
        shell=True,
        stderr=PIPE,
        stdout=PIPE)
    (stdout, stderr) = returnVal.communicate()
    watch_ansible.kill()
    os.unlink(FIFO)
    if returnVal.returncode != 0:
        logger.error("\n\nFailed to execute ansible playbook correctly!!")
        if not continue_on_fail:
            logger.error("Find the stdout and stderr below...\n\n")
            logger.error(stdout)
            logger.error(stderr)
            abortSetup("Ansible playbook error")
        else:
            logger.debug(stdout)
            logger.debug(stderr)
            logger.warning(
                "Continuing deployment; please see logs for failure details.")
            return False
    return True


def killDnsmasq():
    # Function to stop any existing dnsmasq processes
    logger.debug("Killing any existing dnsmasq processes")
    p1 = Popen(shlex.split('ps -e'), stdout=PIPE)
    p2 = Popen(
        shlex.split('grep dnsmasq'),
        stdin=p1.stdout,
        stdout=PIPE,
        stderr=STDOUT)
    pOut, _ = p2.communicate()
    for line in pOut.splitlines():
        if 'dnsmasq' in line:
            pid = int(line.split(None, 1)[0])
            os.kill(pid, signal.SIGKILL)
    logger.debug("Wiping the dnsmasq.leases file")
    host_command("echo '' > /var/lib/dnsmasq/dnsmasq.leases", shell=True)


def startDhcpService():
    # Function to set and initiate services for this node as the deployment master
    global mgmt_subnet

    print "\r\nThe default DHCP subnet is: %s" % str(mgmt_subnet)
    print "If you would prefer to choose another subnet for your"
    print "management network, you may enter it below. Simply press"
    print "Enter to accept the default.\r\n"

    while True:
        input_string = user_input("   DHCP subnet [%s]: " % str(mgmt_subnet))
        if input_string == '':
            break
        try:
            new_mgmt_subnet = IPNetwork(input_string)
        except netaddr.core.AddrFormatError:
            logger.warning("The network input is not a valid IP network")
            continue
        if not new_mgmt_subnet.ip.is_private():
            logger.warning("Please select a private subnet")
            continue
        if (new_mgmt_subnet.size - 2) >= desiredNumOfNodes:
            mgmt_subnet = new_mgmt_subnet
            break
        logger.warning(
            "The entered netwrok is too small to assign each node an IP")

    print "\r\n"
    logger.info("Configuring management network interface...")
    # TODO Will need a better way to identify the management network NIC
    host_command('/bin/systemctl start NetworkManager')
    host_command('/sbin/ip addr flush dev %s' % mgmt_interface)
    host_command(
        '/bin/nmcli con modify --temporary %s ipv4.method manual ipv4.addr %s/%i'
        % (nm_mgmt_interface, mgmt_subnet[1], mgmt_subnet.prefixlen))
    host_command('/bin/nmcli con up %s' % nm_mgmt_interface)
    logger.info("Enabling DHCP service for management network...")
    host_command('/bin/firewall-cmd --add-service=dhcp')
    killDnsmasq()
    # TODO: Discuss subnet for initial DHCP config
    host_command('/sbin/dnsmasq --interface=%s --dhcp-range=%s,%s,12h' %
                 (mgmt_interface, mgmt_subnet[2], mgmt_subnet[-2]))


def stopDhcpService():
    # Function to stop specialized DHCP server
    killDnsmasq()
    host_command('/bin/firewall-cmd --remove-service=dhcp')
    host_command('/bin/nmcli con reload %s' % nm_mgmt_interface)
    host_command('/bin/nmcli con up %s' % nm_mgmt_interface)


def collectDeploymentInformation():
    # Function to set specifics for deployment
    global nodes_min
    global replica
    global replica_count
    global arbiter_count
    global disperse
    global disperse_count
    global redundancy_count
    try:
        if str(oem_id['flavor']['voltype']) == "replica":
            # Set gdeploy values for replica volume type
            nodes_min = 4
            nodes_multiple = 2
            replica = 'yes'
            if str(oem_id['flavor']['arbiter_size']) == "None":
                replica_count = str('\'2\'')
                arbiter_count = str('\'0\'')
            else:
                replica_count = str('\'3\'')
                arbiter_count = str('\'1\'')
            disperse = str('\'no\'')
            disperse_count = str('\'0\'')
            redundancy_count = str('\'0\'')
        elif str(oem_id['flavor']['voltype']) == "disperse":
            # Set gdeploy values for disperse volume type
            nodes_min = 6
            nodes_multiple = 6
            replica = 'no'
            replica_count = str('\'0\'')
            arbiter_count = str('\'0\'')
            disperse = str('\'yes\'')
            disperse_count = str('\'4\'')
            redundancy_count = str('\'2\'')
        else:
            abortSetup("Error: Invalid voltype detected in OEMID file")
    except:
        abortSetup("Error: No voltype defined in OEMID file")

    # Get number of Gluster nodes from user
    print("\r\nHow many %s nodes are you deploying?" % brand_short)
    while True:
        try:
            input_string = int(
                user_input("\r\n   Number of nodes (valid range is %i-%i): " %
                           (nodes_min, nodes_max)))
        except ValueError:
            logger.error("Please enter a valid integer\n")
            continue
        global desiredNumOfNodes
        desiredNumOfNodes = int(input_string) if input_string else 0
        if desiredNumOfNodes < nodes_min or desiredNumOfNodes > nodes_max:
            logger.error(
                "The number is outside of the supported range. Please try again.\n"
            )
        elif desiredNumOfNodes % nodes_multiple != 0:
            logger.error(
                "The number must be a multiple of %i. Please try again.\n" %
                nodes_multiple)
        else:
            break

    logger.debug("Deploying %i nodes" % int(desiredNumOfNodes))

    print "\r\nWe will now configure the Gluster nodes for your storage network."
    print "Please ensure that all cabling and switch configuration is"
    print "complete before proceeding."

    print "\r\nBe prepared to provide network information for all nodes in"
    print "your Gluster deployment, including:\r\n"

    print "   * hostnames"
    print "   * IP addresses"
    print "   * subnet mask"
    print "   * default gateway"
    print "   * DNS servers\r\n"

    yes_no('Do you wish to continue? [Y/n] ')

    print "\r\nAll nodes are expected to be on the same storage subnet, so we"
    print "will first collect all shared network information.\r\n"

    # Get global network information from user
    while True:
        input_string = user_input("   Storage network domain name: ")
        global domain_name
        domain_name = input_string.lower()
        # regular expression to validate domain name based on RFCs
        domain_check = re.compile(
            "^(?=.{1,253}$)(?!.*\.\..*)(?!\..*)([a-zA-Z0-9-]{,63}\.){,127}[a-zA-Z0-9-]{1,63}$"
        )
        isdomain = domain_check.match(domain_name)
        if isdomain is None:
            logger.warning("The domain name string is invalid")
            continue
        break

    logger.debug("Domain name is %s" % str(domain_name))

    while True:
        input_string = user_input(
            "   Storage network and CIDR mask (eg, 10.10.10.0/24): ")
        try:
            global storage_subnet
            storage_subnet = IPNetwork(input_string)
        except netaddr.core.AddrFormatError:
            logger.warning("The network input is not a valid IP network")
            continue
        # Substract first and last IPs (Broadcast)
        if (storage_subnet.size - 2) >= desiredNumOfNodes:
            break
        logger.warning(
            "The entered network is too small to assign each node an IP")

    logger.debug("Storage network is %s" % str(storage_subnet))

    print "\r\nGateway and DNS fields may be left blank for now, if you prefer.\r\n"

    global gatewayAddress
    gatewayAddress = ipValidator("   Gateway IP address: ", null_valid=True)

    if gatewayAddress is not '':
        global dnsServerAddress
        for i in range(2):
            dnsnum = i + 1
            dns = ipValidator(
                "   DNS%i server address: " % dnsnum,
                null_valid=True,
                check_dupes=False,
                check_subnet=False)
            dnsServerAddress.append(str(dns))
            if dns is '':
                if dnsnum is 1:
                    dnsServerAddress.append('')
                break

    print "\r\nNTP will be configured for time synchronization. You may enter"
    print "up to four NTP servers below. If you would prefer to use the RHEL"
    print "public NTP servers, simply press Enter at the first prompt and the"
    print "default servers will be applied.\r\n"

    print "NOTE: Using the default public NTP servers requires that all of the"
    print "      %s nodes have access to the Internet\r\n" % brand_short

    global ntpServers
    ntpServers = []

    #TODO: Add data validation
    for i in range(4):
        if i is 0:
            ntpInput = user_input("NTP Server %i (press Enter to accept defaults): " % int(i+1))
        else:
            ntpInput = user_input("NTP Server %i: " % int(i+1))
        if ntpInput is '':
            break
        else:
            ntpServers.append(ntpInput)
            logger.debug("NTP server %i is %s" % (int(i+1), str(ntpInput)))

    if not ntpServers:
        logger.debug("NTP servers not defined; using defaults")
        update_ntp = False
    else:
        update_ntp = True


def collectNodeInformation():
    logger.debug("Manually assigning node info...")
    # Function to manually collect node specifics from user
    print "\r\nWe will now collect all node-specific storage network information."
    logger.debug("Collecting node network information...")
    global nodeInfo
    nodeInfo = {}
    host_interface_information = {}
    for idx, node in enumerate(g1Hosts):
        nodeNum = str(idx + 1)
        nodeInfo[nodeNum] = {}
        print "\r\nNode %i:" % int(nodeNum)
        nodeInfo[nodeNum]['node'] = node
        while True:
            input_string = user_input("   Hostname (short): ")
            hostname = input_string.lower()
            hostname_check = re.compile("^[a-zA-Z0-9-]{1,64}$")
            ishostname = hostname_check.match(hostname)
            if ishostname is None:
                logger.warning("The hostname entered is invalid")
                continue
            nodeInfo[nodeNum]['hostname'] = str(hostname)
            break

        nodeInfo[nodeNum]['ip'] = ipValidator("   Storage IP address: ")

        host_interface_information[node + "-" + nm_mgmt_interface] = {
            "ifname":
            nm_mgmt_interface,
            "ifip":
            str(node),
            "hostname":
            str(nodeInfo[nodeNum]['hostname']) + "." + str(domain_name),
            "runOn":
            node,
            "netprefix":
            mgmt_subnet.prefixlen,
            "gwaddress":
            "",
            "dnsaddress":
            dnsServerAddress
        }
        host_interface_information[node + "-" + storage_interface] = {
            "ifname":
            storage_interface,
            "ifip":
            str(nodeInfo[nodeNum]['ip']),
            "hostname":
            str(nodeInfo[nodeNum]['hostname']) + '.' + str(domain_name),
            "runOn":
            node,
            "netprefix":
            storage_subnet.prefixlen,
            "gwaddress":
            str(gatewayAddress),
            "dnsaddress":
            dnsServerAddress
        }

    logger.info("All node info successfully collected")
    logger.debug("Node info: %s" % str(nodeInfo))

    global vip_list
    global vips
    vip_list = []
    vips = []

    # Enumerate the list of VIPs if we are using the NFS client
    if use_nfs:
        print "\r\nYour deployment will be configured with %i NFS-Ganesha HA nodes." % int(
            ha_node_count)
        print "You will need to provide a VIP from the %s subnet for each of the nodes.\r\n" % str(
            storage_subnet)
        for i in range(int(ha_node_count)):
            vipNum = str(i + 1)
            vip = ipValidator("   VIP address %s: " % str(vipNum))
            vips.append(str(vip))
            vip_list.append("VIP_%s.%s=\"%s\"" %
                            (str(nodeInfo[str(i + 1)]['hostname']),
                             str(domain_name), str(vip)))
        vip_list = natural_sort(vip_list)

    return host_interface_information


def autoNodeInformation():
    logger.debug("Auto-assigning node info...")
    # Function to automatically assign node specifics
    host_interface_information = {}
    storageIPCounter = 0
    global nodeInfo
    nodeInfo = {}

    for idx, node in enumerate(g1Hosts):
        nodeNum = str(idx + 1)
        nodeInfo[nodeNum] = {}
        nodeInfo[nodeNum]['node'] = node
        while True:
            storageIPCounter += 1
            if storageIPCounter > (storage_subnet.size - 2):
                abortSetup("Ran out of IPs for automatic assignment!")
            ip = str(storage_subnet[storageIPCounter])
            if str(ip) in consumed_ips:
                continue
            consumed_ips.append(str(ip))
            nodeInfo[nodeNum]['ip'] = str(ip)
            break

        nodeInfo[nodeNum]['hostname'] = "g1-" + str(nodeNum)

        host_interface_information[node + "-" + nm_mgmt_interface] = {
            "ifname":
            nm_mgmt_interface,
            "ifip":
            str(node),
            "hostname":
            str(nodeInfo[nodeNum]['hostname']) + "." + str(domain_name),
            "runOn":
            node,
            "netprefix":
            mgmt_subnet.prefixlen,
            "gwaddress":
            "",
            "dnsaddress":
            dnsServerAddress
        }
        host_interface_information[node + "-" + storage_interface] = {
            "ifname":
            storage_interface,
            "ifip":
            str(nodeInfo[nodeNum]['ip']),
            "hostname":
            str(nodeInfo[nodeNum]['hostname']) + "." + str(domain_name),
            "runOn":
            node,
            "netprefix":
            storage_subnet.prefixlen,
            "gwaddress":
            str(gatewayAddress),
            "dnsaddress":
            dnsServerAddress
        }

    logger.debug("Node info: %s" % str(nodeInfo))
    logger.info("All node info successfully assigned")

    global vip_list
    global vips
    vip_list = []
    vips = []

    # Enumerate the list of VIPs if we are using the NFS client
    if use_nfs:
        logger.debug("Assigning VIPs")
        for i in range(int(ha_node_count)):
            storageIPCounter += 1
            while True:
                if storage_subnet[storageIPCounter] == gatewayAddress or storage_subnet[storageIPCounter] == dnsServerAddress:
                    storageIPCounter += 1
                    continue
                break
            vips.append(str(storage_subnet[storageIPCounter]))
            vip_list.append("VIP_%s.%s=\"%s\"" %
                            (str(nodeInfo[str(i + 1)]['hostname']),
                             str(domain_name),
                             str(storage_subnet[storageIPCounter])))
        logger.debug("VIP list is: %s" % str(vip_list))

    return host_interface_information


#Main program section
try:
    print brand_banner

    print "\r\nWelcome to the \033[31m%s %s\033[0m deployment tool!\r\n" % (
        brand_parent, brand_project)

    print "This node will be configured as the deployment master for your"
    print "Gluster storage pool. Before proceeding, please ensure that"
    print "all %s nodes are connected to the management" % brand_short
    print "network infrastructure and are booted.\r\n"

    yes_no('Do you wish to continue? [Y/n] ')

    logger.debug("** Begin %s %s**" % (brand_parent, brand_project))

    # === PHASE 1 ===
    # NOTE: The purpose of this initial phase of deployment is to dynamically
    # build the node inventory

    print "\r\n"
    logger.info("Begin %s inventory phase" % brand_short)
    print "\r\n"

    # Tell the user what we expect to deploy based on OEMID files
    logger.info("Your deployment node type is \t\033[31m" +
                oem_id['flavor']['node']['name'] + "\033[0m")
    logger.info("Your deployment flavor is \t\033[31m" +
                oem_id['flavor']['name'] + "\033[0m")

    # Collect the global deployment details from the user
    collectDeploymentInformation()

    logger.debug("Ansible inventory file: " + peerInventory)
    f = open(peerInventory, 'w')
    f.write("[gluster_nodes]\r\n")
    f.close()

    print "\r\n"

    logger.info(
        "\033[31mConfiguring this node as the deployment master...\033[0m")

    print "\r\n"

    # Set this node up as the deployment master
    print "The Gluster colonizer requires DHCP service on the management"
    print "network. If the service is not already available on the"
    print "management network, we can start a temporary DHCP server on this"
    print "node now. This local DHCP service will only operate for the"
    print "duration of the deployment process.\r\n"

    start_dhcp = yes_no('Do you wish to start the DHCP service here? [y/N] ',
                        do_return=True, default='no')

    print "\r\n"

    if start_dhcp:
        logger.info("Configuring local DHCP service...")
        startDhcpService()
        logger.debug("Management subnet is %s" % mgmt_subnet)
    else:
        logger.info("Proceeding with external DHCP service")
        print "\r\n"
        logger.info("Detecting management subnet...")
        #HERE
        #TODO: This needs improvement to get rid of the shell approach
        while True:
            try:
                host_command('/bin/systemctl start NetworkManager')
                p1 = Popen(shlex.split('/bin/nmcli con show %s' % nm_mgmt_interface), stdout=PIPE)
                p2 = Popen(shlex.split('grep IP4.ADDRESS\\\\[1\\\\]'), stdin=p1.stdout, stdout=PIPE)
                p3 = Popen(shlex.split('awk "{print $2}"'), stdin=p2.stdout, stdout=PIPE)
                p1.stdout.close()
                p2.stdout.close()
                ip = IPNetwork(p3.communicate()[0])
                mgmt_subnet = IPNetwork("%s/%s" % (ip.network, ip.prefixlen))
                break
            except:
                logger.warning("Unable to detect management network")
                logger.warning("Please ensure the DHCP service is available")
                yes_no('Do you wish to attempt detection again? [Y/n] ')
                print "\r\n"
                continue
        logger.info("Management subnet is %s" % mgmt_subnet)

    print "\r\n"

    yes_no("We will now begin node discovery. Do you wish to continue? [Y/n] ")

    print "\r\n"

    logger.info("Searching for %i %s nodes." % (desiredNumOfNodes,
                                                brand_short))
    print "This may take several minutes while all nodes come online...\r\n"

    currentNumOfHosts = 0
    g1Hosts = []

    logger.debug("Building Ansible host inventory...")

    # Get nodes from gluster-discovery (gluster-zeroconf project)
    #TODO: Add logic for validation of hosts and check for duplicates.
    #Possibly borrow from dnsmasq-lease-interpreter.py script
    #TODO: Check for if we found too many nodes
    node_search_timeout = 20  #attempts
    counter = 1
    discovery_file = "/var/tmp/gluster-discovery.out-" + "".join(
        random.sample(rand_filename_sample, rand_filename_len))
    while (currentNumOfHosts) < desiredNumOfNodes:
        g1Hosts = []
        pOut = open(discovery_file, 'w')
        p1 = Popen("/bin/gluster-discovery", stdout=PIPE, shell=True)
        p2 = Popen(shlex.split("sort -u"), stdin=p1.stdout, stdout=pOut)
        p1.stdout.close()
        output = p2.communicate()[0]
        pOut.close()
        #FIXME: The gluster-discovery tool returns host IPs non-deterministically.
        #       Need a check to ensure IPs are on the right subnet.
        # Checking all subnet IPs except network and broadcast
        with open(discovery_file, 'r') as source:
            # Will read only the desired number of nodes (lines)
            discoveries = source.readlines()
            ips = []
            for discovery in discoveries:
                discovered_ip = discovery.split()[2]
                try:
                    if discovered_ip not in mgmt_subnet:
                        continue
                # Any connected peers may separately report hostnames instead of IPs
                except AddrFormatError:
                    continue
                try:
                    ips.append(discovered_ip)
                except IndexError:
                    continue
            g1Hosts = ips[:desiredNumOfNodes]
        currentNumOfHosts = len(g1Hosts)
        if currentNumOfHosts == 1:
            print 'Found %i node so far...  %i attempts remaining   \r' % (
                currentNumOfHosts, int(node_search_timeout) - int(counter)),
            sys.stdout.flush()
        #TODO: Add check for too many hosts
        else:
            print 'Found %i nodes so far...  %i attempts remaining   \r' % (
                currentNumOfHosts, int(node_search_timeout) - int(counter)),
            sys.stdout.flush()
        time.sleep(1)
        counter += 1
        if counter > node_search_timeout:
            abortSetup(
                "Timeout searching for nodes. Ensure all nodes are online and connected."
            )

    # Remove \n from end of each line and merge lines with commas
    g1Hosts = [s.rstrip() for s in g1Hosts]
    g1_inventory = ','.join(map(str, g1Hosts))

    print "\r\n"
    logger.info("All nodes located.")

    # Write the ansible inventory file
    with open(peerInventory, 'a') as inventory:
        for host in g1Hosts:
            inventory.write(host + "\r\n")

    logger.info("Inventory complete.")
    logger.debug("Ansible inventory: " + g1_inventory)

    print "\r\nPlease choose the client access method you will use for the"
    print "default storage volume. This applies only to the volume that is"
    print "automatically created during deployment, and the method can be"
    print "changed manually post-install.\r\n"
    print "    1. NFS"
    print "    2. Gluster Native Client (FUSE)\r\n"

    # User selects client access method
    use_nfs = False
    min_ha_nodes = 4
    max_ha_nodes = 16
    # Total nodes per HA node; 1.5 equals 2 HA nodes for every 3 nodes
    ha_node_factor = 1.5
    global mount_protocol
    global mount_protocol_name
    while True:
        input_string = user_input("Client method? [1] ")
        if str(input_string) is "2":
            logger.info("Gluster Native Client selected")
            mount_protocol = "glusterfs"
            mount_protocol_name = "Gluster native client"
            ha_node_count = 0
            break
        elif str(input_string) is "1" or input_string is "":
            logger.info("NFS Client selected")
            mount_protocol = "nfs"
            mount_protocol_name = "NFS"
            use_nfs = True
            #TODO: Double-check that this calculation works correctly.
            #      The quotient should be a float value, and the math.ceil
            #      function should round this up.
            ha_node_count = int(
                math.ceil(int(len(g1Hosts)) / float(ha_node_factor)))
            if int(ha_node_count) < int(min_ha_nodes):
                ha_node_count = int(min_ha_nodes)
            elif int(ha_node_count) > int(max_ha_nodes):
                ha_node_count = int(max_ha_nodes)
            logger.debug("HA node count is %i" % int(ha_node_count))
            break
        else:
            logger.warning("Please select from the list.\r\n")
            continue

    print "\r\nYou may choose to either assign production storage network"
    print "hostnames and static IP addresses to your nodes manually, or"
    print "the deployment tool can assign them for you automatically from"
    print "the %s network." % str(storage_subnet)
    print "\r"
    print "\033[31mNOTE: These hostnames and IP adresses are expected to remain"
    print "      static, so please choose your values carefully. If you"
    print "      choose automatic assignment, the deployment tool assumes"
    print "      that there are no other devices on the storage network"
    print "      and that all IPs are available to use.\033[0m"
    print "\r\n"

    # User selects manual or automatic storage network detail assignment
    while True:
        input_string = user_input(
            "Would you like to proceed with (m)anual or (a)utomatic assignment? [m/a] "
        )
        if str(input_string).lower() == "m" or str(
                input_string).lower() == "manual":
            host_interface_information = collectNodeInformation()
            break
        elif str(input_string).lower() == "a" or str(
                input_string).lower() == "automatic":
            host_interface_information = autoNodeInformation()
            break
        else:
            logger.warning("Please enter either (m)anual or (a)utomatic.\r\n")
            continue

    # Add all hostnames to a list for peer probing and building the brick string
    hostnames = []
    for node in sorted(nodeInfo):
        hostnames.append(str(nodeInfo[node]['hostname']))
    hostnames = natural_sort(hostnames)

    logger.debug("Hostnames are %s" % str(hostnames))

    # Enumerate the HA node list for NFS-Ganesha
    ha_cluster_nodes = ''
    hacluster_password = ''
    if use_nfs:
        for i in range(int(ha_node_count)):
            if i != 0:
                ha_cluster_nodes = ha_cluster_nodes + ","
            ha_cluster_nodes = ha_cluster_nodes + str(
                hostnames[i]) + '.' + str(domain_name)
        # Generate random hacluster password
        s = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()?"
        passlen = 20
        hacluster_password = "".join(random.sample(s, passlen))

    logger.debug("HA nodes are %s" % str(ha_cluster_nodes))

    print "\r\n"

    print "Please confirm your deployment details:"

    print "\r\n"

    print "Domain name:  %s" % str(domain_name)

    print "Storage network:  %s" % str(storage_subnet)

    print "Default gateway: ",
    print str(gatewayAddress) if gatewayAddress is not "" else "skipped"

    for i in (1, 2):
        print "DNS %i: " % i,
        print str(dnsServerAddress[int(
            i - 1)]) if dnsServerAddress and dnsServerAddress[int(
                i - 1)] is not "" else "skipped"

    print "\r"

    print "Storage nodes:"
    print "{:<25} {:<25}".format('Hostname', 'IP Address')
    for k, v in nodeInfo.iteritems():
        print "{:<25} {:<25}".format('%s.%s' %
                                     (str(v['hostname']), str(domain_name)),
                                     str(v['ip']))

    if use_nfs:
        print "\r"
        print "Virtual IPs (VIPs):"
        for vip in vips:
            print str(vip)

    print "\r\n"

    yes_no("Do you wish to continue with this configuration? [Y/n] ")

    print "\r\n"

    # Define the default mount host and mount options
    mount_opts = "defaults,_netdev"
    if use_nfs:
        mount_host = str(vips[0])
    else:
        mount_host = "%s.%s" % (str(nodeInfo['1']['hostname']),
                                str(domain_name))
        mount_opts += ",backupvolfile-server="
        for count, _ in enumerate(nodeInfo):
            if count == 0:
                continue
            mount_opts += "%s.%s" % (str(nodeInfo[str(count + 1)]['hostname']),
                                     str(domain_name))
            if count != len(nodeInfo) - 1:
                mount_opts += ":"

    # Create and deploy new ssh keys for ansible user
    print "Your systems have factory SSH keys for the ansible user. These"
    print "keys \033[31mshould not be considered secure\033[0m. It is highly recommended"
    print "that we replace these keys now with a newly-generated set.\r\n"
    new_ssh_keys = yes_no(
        'Would you like to proceed with creating a new set of SSH keys? [Y/n] ',
        True)

    print "\r\n"

    if new_ssh_keys:
        logger.info("New ansible user SSH keys will be exchanged")
    else:
        logger.warning("Existing ansible user SSH keys will be kept")

    # Reset root password
    print "\r\nThe default root password on your %s nodes must be reset." % brand_short
    print "\033[31mBe careful to select a secure password, and note that the"
    print "password will be updated for the root user on all nodes.\033[0m\r\n"

    while True:
        # random password salt
        pwsalt = ''.join(
            random.SystemRandom().choice(string.ascii_letters + string.digits)
            for _ in range(8))
        try:
            root_password_hashed = crypt.crypt(
                getpass.getpass("Please enter the new root password: "),
                "$6$" + pwsalt)
        except Exception as err:
            print('ERROR:', err)
        # check for blank password
        if root_password_hashed == crypt.crypt('', "$6$" + pwsalt):
            continue
        # confirm password
        if root_password_hashed == crypt.crypt(
                getpass.getpass("Confirm password: "), "$6$" + pwsalt):
            logger.info("New root password collected")
            break
        else:
            print "Passwords do not match!\r\n"
            continue

    # === PHASE 2 ===
    # NOTE: Validate all nodes against the OEMID file

    print "\r\n"
    logger.info("Begin %s validation phase" % brand_short)
    print "\r\n"

    # Check each node against expectations in OEMID file
    logger.info("Comparing nodes to expected configurations...")
    run_ansible_playbook(g1_path + 'oemid/' +
                         oem_id['flavor']['node']['verify_file_name'])
    logger.info("All node validations passed")

    # === PHASE 3 ===
    # NOTE: Initiate deployment

    print "\r\n"
    logger.info("Begin %s deployment phase" % brand_short)
    print "\r\n"

    yes_no('Next we will initiate the Gluster installation - OK? [Y/n] ')
    print "\r\n"
    print "\033[31mWARNING: This step will delete any existing Gluster configurations"
    print "         and will wipe the LVM block devices and filesystems for drives"
    print "         other than the system drive."
    print "\r"
    print "         THIS WILL DELETE ANY EXISTING DATA FROM THE SYSTEMS!\033[0m\r\n"
    yes_no('Are you sure you want to continue? [Y/n] ')

    print("\r\nPlease be patient; these steps may take a while...\r\n")

    logger.info("Initiating Gluster deployment...")

    # Build the backend configuration dictionary from the OEMID file
    brickcount = 1
    backend_configuration = []
    for idx, device in enumerate(oem_id['flavor']['node']['backend_devices']):
        backend_configuration += [{
            'id':
            idx,
            'thinLV':
            'brick' + str(brickcount),
            'tp':
            'TP' + str(brickcount),
            'vg':
            'VG' + str(brickcount),
            'device':
            str(device),
            'arbiter_size':
            str(oem_id['flavor']['arbiter_size'])
        }]
        brickcount += 1
    logger.debug("Backend config" + str(backend_configuration))

    # Populate cache devices and size
    # TODO: make the cache devices optional
    cache_devices = []
    try:
        cache_devices = str(oem_id['flavor']['node']['cache_devices'])
    except:
        abortSetup("No cache device defined in OEMID file")
    cache_part_size = 100 / len(oem_id['flavor']['node']['backend_devices'])

    # TODO: I suspect there is a more pythonic way to handle the below with fewer lines
    # Build replica peer sets if the voltype is replica
    if str(oem_id['flavor']['voltype']) == "replica":
        logging.debug("Building replica peer sets...")
        bricks_per_node = len(oem_id['flavor']['node']['backend_devices'])
        replica_peers = []
        for i in range(bricks_per_node):
            for node in natural_sort(hostnames):
                replica_peers += [{
                    'node':
                    node,
                    'brick':
                    '/gluster/bricks/%s' %
                    str(backend_configuration[i]['thinLV'])
                }]

        peer_set_num = 0
        peer_set = []
        for count, brick in enumerate(replica_peers):
            if count % 2 == 0:
                peer_set.insert(peer_set_num, [brick])
            else:
                peer_set[peer_set_num].append(brick)
                logger.debug("Replica peer set %i is %s" %
                             (peer_set_num, peer_set[peer_set_num]))
                peer_set_num += 1

        # Add the arbiter bricks if the arbiter_size is defined in the OEMID file
        if str(oem_id['flavor']['arbiter_size']) != "None":
            logger.debug("Adding arbiter bricks to replica peer sets...")
            peer_set_num = 0
            for count, device in enumerate(
                    oem_id['flavor']['node']['backend_devices']):
                arbiter_counter = 2
                #FIXME: Hard-coded based on replica 2
                # for number of nodes / number of replicas (2)
                for host_group in range(len(hostnames) / 2):
                    pair = peer_set[peer_set_num]
                    arbiter_node = natural_sort(hostnames)[arbiter_counter]
                    pair.append({
                        'node':
                        arbiter_node,
                        'brick':
                        '/gluster/bricks/arbiter-%s' %
                        str(backend_configuration[count]['thinLV'])
                    })
                    logger.debug("Arbitrated replica peer set %i is %s" %
                                 (peer_set_num, peer_set[peer_set_num]))
                    if host_group == 0:
                        arbiter_counter = 1
                    else:
                        arbiter_counter += 2
                    peer_set_num += 1

        # List-ify the peer sets
        peer_list_min = []
        peer_list_remain = []
        for counter, group in enumerate(peer_set):
            #FIXME: Hard-coded based on replica 2
            if counter < (int(nodes_min) / 2):
                peer_list_min += group
            else:
                peer_list_remain += group

    #FIXME: Clean up this ugly mess
    # Build the ansible playbook arguments
    playbook_args = playbook_path + '/g1-deploy.yml --extra-vars="{cache_devices: ' + str(
        cache_devices
    ) + ',part_size: ' + str(cache_part_size) + ',hostnames: ' + str(
        hostnames
    ) + ',domain_name: ' + str(domain_name) + ',dalign: ' + str(
        oem_id['flavor']['node']['dalign']
    ) + ',diskcount: ' + str(
        oem_id['flavor']['node']['diskcount']
    ) + ',numdevices: ' + str(
        len(oem_id['flavor']['node']['backend_devices'])
    ) + ',disktype: ' + str(
        oem_id['flavor']['node']['disktype']
    ) + ',force: no' + ',backend_configuration: ' + str(
        backend_configuration
    ) + ',replica: ' + str(replica) + ',replica_count: ' + str(
        replica_count
    ) + ',arbiter_count: ' + str(arbiter_count) + ',disperse: ' + str(
        disperse
    ) + ',disperse_count: ' + str(disperse_count) + ',redundancy_count: ' + str(
        redundancy_count
    ) + ',use_nfs: ' + str(use_nfs) + ',vip_list: ' + str(
        vip_list
    ) + ',ha_cluster_nodes: \'' + str(
        ha_cluster_nodes
    ) + '\'' + ',hacluster_password: \'' + str(
        hacluster_password) + '\'' + ',default_volname: ' + str(
            default_volname) + ',network_config: ' + str(
                host_interface_information
            ) + ',nodeInfo: ' + str(nodeInfo) + ',storage_interface: ' + str(
                storage_interface
            ) + ',brand_distributor: ' + str(
                brand_distributor
            ) + ',brand_parent: ' + str(
                brand_parent
            ) + ',brand_project: ' + str(
                brand_project
            ) + ',brand_short: ' + str(brand_short) + ',readme_file: \'' + str(
                readme_file) + '\',mount_protocol: ' + str(
                    mount_protocol) + ',mount_host: ' + str(
                        mount_host) + ',mount_opts: \'' + str(
                            mount_opts
                        ) + '\'' + ',vips: ' + str(vips) + ',nodes_min: ' + str(
                            nodes_min) + ',nodes_deployed: ' + str(
                                desiredNumOfNodes) + ',tuned_profile: ' + str(
                                    oem_id['flavor']['node']['tuned']
                                ) + ',gluster_vol_set: ' + str(
                                    oem_id['flavor']['node']['gluster_vol_set']
                                ) + ',root_password_hashed: ' + re.sub(
                                    '\$', '\\\$', root_password_hashed)

    if 'peer_set' in globals():
        playbook_args += ',replica_peers: ' + str(peer_list_min)

    global arbiter
    if str(oem_id['flavor']['arbiter_size']) != "None":
        arbiter = True
    else:
        arbiter = False
    playbook_args += ',arbiter: ' + str(arbiter)

    playbook_args += ',update_ntp: ' + str(update_ntp)
    if update_ntp:
        playbook_args += ',ntpServers: ' + str(ntpServers)

    playbook_args += '}"'

    # Run playbook to replace ansible user ssh keys
    if new_ssh_keys:
        run_ansible_playbook(playbook_path + "/g1-key-dist.yml")

    # Run the primary g1-deploy ansible playbook
    run_ansible_playbook(playbook_args)

    print "\r\n"

    logger.info("Your \033[31m%s %s\033[0m deployment is now complete!" %
                (brand_parent, brand_project))

    print "\r\n"

    print "You have the option to run a series of performance tests to validate"
    print "your %s environment. The performance tests can take an" % brand_short
    print "hour or longer to complete. It is recommended that you perform these"
    print "tests now, but you may also choose to run them at a later time."

    print "\r"

    run_perf_tests = yes_no(
        'Would you like to start the performance tests now? [Y/n] ', True)

    print "\r\n"

    if run_perf_tests:
        logger.info("Beginning performance tests. Please be patient...")
        playbook_args = playbook_path + '/g1-perf-test.yml --extra-vars="{default_volname: ' + str(
            default_volname
        ) + ',hostnames: ' + str(hostnames) + ',arbiter: ' + str(
            arbiter) + ',perf_jobfile: ' + str(
                perf_jobfile) + ',perf_server_list: ' + str(
                    perf_server_list) + ',perf_output : ' + str(perf_output)
        if 'peer_set' in globals():
            playbook_args += ',replica_peers: ' + str(peer_list_min)
        playbook_args += '}"'
        perf_tests_complete = run_ansible_playbook(
            playbook_args, continue_on_fail=True)
        if perf_tests_complete:
            logger.info("Performance tests complete. Results at: %s" %
                        str(perf_output))
        else:
            logger.warning(
                "Performance tests failed. Please see log for more information."
            )
    else:
        logger.warning("Performance tests skipped")
        #TODO: Add instructions for running the performance tests later

    print "\r\n"

    logger.info(
        "Information about your deployment is available in the %s file\r\n" %
        readme_file)
    raw_input("Press Enter to display the file contents.")

    print "\r\n"

    with open(readme_file, 'r') as readme:
        lines = readme.readlines()
        for line in lines:
            print(line),

    print("\r\n")

    print "The above information is available in %s\r\n" % readme_file

except (KeyboardInterrupt, EOFError):
    # Will catch Ctrl+C
    print "\r\n"
    abortSetup("Keyboard Interrupt detected! Exiting!")
