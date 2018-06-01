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

def flavorVars(logger, abortSetup):
    print "\r\nIn order to bootstrap the block devices on your nodes, the"
    print "hpssacli utility is required. If this utility is not available"
    print "from a currently-configured yum repository on the nodes, it can"
    print "be automatically installed from the HPE ServicePack for Proliant"
    print "repository via the Internet.\r\n"

    global install_hpssacli
    enable_hpe_spp = yes_no('Do you wish to enable the remote repository? [Y/n] ', do_return=True)

    logger.info("Enabling remote repository for hpssacli utility")

    print "\r\nNOTE: If your storage network interface is a bond or team device, it must"
    print "be configured on all nodes before proceeding. A helper playbook is available"
    print "at resources/helper-playbooks/g1-helper-bonding.yml to assist with the"
    print "automated configuration of bonding via Ansible.\r\n"

    yes_no('Do you wish to continue? [Y/n] ', abortSetup)

    return 'enable_hpe_spp: %s' % enable_hpe_spp
