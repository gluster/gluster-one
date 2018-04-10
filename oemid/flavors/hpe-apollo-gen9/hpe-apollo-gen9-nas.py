#*******************************************************************************
#                                                                              *
#  Copyright (c) 2018 Red Hat, Inc. <http://www.redhat.com>                    *
#                                                                              *
#  This file is licensed to you under the GNU General Public License,          *
#  version 3 (GPLv3), as published by the Free Software Foundation             *
#------------------------------------------------------------------------------*
#                                                                              *
# hpe-apollo-gen9-nas.py:  This module allows for customized input and logic   *
#                          for the model and flavor indicated.                 *
#*******************************************************************************

from g1modules import yes_no, user_input

def flavorVars(logger):
    print "\r\nIn order to bootstrap the block devices on your nodes, the"
    print "hpssacli utility is required. If this utility is not available"
    print "from a currently-configured yum repository on the nodes, it can"
    print "be automatically installed from the HPE ServicePack for Proliant"
    print "repository via the Internet.\r\n"

    global install_hpssacli
    enable_hpe_spp = yes_no('Do you wish to enable the remote repository? [Y/n] ', True)

    print "\r\nNetwork interface bonding will be configured for your storage"
    print "network interfaces. Either LACP (aka mode 4, 802.3ad) or TLB"
    print "(aka mode 5, balance-tlb) is supported. Note that LACP requires"
    print "that the switch interface ports are already configured for this"
    print "mode.\r\n"


    global bonding_mode
    while True:
        valid_modes = ['lacp', 'tlb']
        input_string = user_input("Do you wish to use 'lacp' or 'tlb' bonding? [LACP/tlb] ")
        bonding_mode = str(input_string).lower()
        if bonding_mode is '':
            bonding_mode = 'lacp'
        if bonding_mode not in valid_modes:
            logger.warning("Please enter either 'lacp' or 'tlb'")
            continue
        break

    return 'enable_hpe_spp: %s, bonding_mode: %s' % (enable_hpe_spp, bonding_mode)
