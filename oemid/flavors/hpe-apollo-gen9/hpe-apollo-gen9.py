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
    enable_hpe_spp = yes_no('Do you wish to enable the remote repository? [Y/n] ', do_return=True)

    logger.info("Enabling remote repository for hpssacli utility")

    # NOTE: Disabling inline bonding configuration in favor of pre-configuration.
    # A helper playbook has been added at resources/helper-playbooks/g1-helper-bonding.yml
    #print "\r\nNetwork interface bonding will be configured for your storage"
    #print "network interfaces. Either LACP (aka mode 4, 802.3ad) or TLB"
    #print "(aka mode 5, balance-tlb) is supported. Note that LACP requires"
    #print "that the switch interface ports are already configured for this"
    #print "mode.\r\n"
    #print "   1. LACP"
    #print "   2. TLB\r\n"
    #
    #
    ##NOTE: The bonding_mode should be set based on the ansible nmcli module
    ##      allowed values
    #global bonding_mode
    #while True:
    #    input_string = user_input("Bonding mode? [1] ") or "1"
    #    if str(input_string) is "1":
    #        logger.info("LACP bonding mode selected")
    #        bonding_mode = "802.3ad"
    #        break
    #    elif str(input_string) is "2":
    #        logger.info("TLB bonding mode selected")
    #        bonding_mode = "balance-tlb"
    #        break
    #    else:
    #        logger.warning("Please select from the list.\r\n")
    #        continue
    #
    #return 'enable_hpe_spp: %s, bonding_mode: %s' % (enable_hpe_spp, bonding_mode)

    print "\r\nNOTE: If your storage network interface is a bond or team device, it must"
    print "be configured on all nodes before proceeding. A helper playbook is available"
    print "at resources/helper-playbooks/g1-helper-bonding.yml to assist with the"
    print "automated configuration of bonding via Ansible.\r\n"

    yes_no('Do you wish to continue? [Y/n] ', abortSetup)

    return 'enable_hpe_spp: %s' % enable_hpe_spp
