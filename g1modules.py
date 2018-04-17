from termios import tcflush, TCIOFLUSH
import logging
import sys
import readline
from subprocess import *
import shlex

def setupLogging(args, logfile):
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
    logfileHandler = logging.FileHandler(logfile)
    logfileHandler.setLevel(logging.DEBUG)
    logfileFormatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s')
    logfileHandler.setFormatter(logfileFormatter)
    # Add handlers to logger
    logger.addHandler(consoleHandler)
    logger.addHandler(logfileHandler)
    return logger

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

def user_input(msg, initial=''):
    # Function to capture raw_input w/ key buffer flush
    tcflush(sys.stdin, TCIOFLUSH)
    readline.set_startup_hook(lambda: readline.insert_text(initial))
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

def stopDhcpService():
    # Function to stop specialized DHCP server
    killDnsmasq()
    host_command('/bin/firewall-cmd --remove-service=dhcp')
    host_command('/bin/nmcli con reload %s' % nm_mgmt_interface)
    host_command('/bin/nmcli con up %s' % nm_mgmt_interface)

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

