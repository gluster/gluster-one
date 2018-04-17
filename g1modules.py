from termios import tcflush, TCIOFLUSH
import logging
import sys
import readline

def setupLogging(args):
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
