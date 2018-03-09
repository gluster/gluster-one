# Gluster Colonizer
The **Gluster Colonizer** is an opinionated node executor for Gluster that aids in very quick deployments.

## What are we doing here?
The Colonizer is an overlay toolkit for deploying gluster via pre-defined and opinionated constructs. It is a combination of python scripts, YAML files, Ansible playbooks, gdeploy modules, baling twine, eye of newt, and true love's kiss.

The intention of the Colonizer is to provide a single user interface for a Gluster deployment with minimal prerequisites for the user and minimal inputs at deployment time. Accomplishing this requires that we pre-identify a *flavor* for the deployment. A flavor is a workload-optimized stack of (expected) hardware components, system-level configurations, and Gluster volume geometries and settings. The flavor is defined via a set YAML *OEMID* files and is used both to validate the nodes for the deployment and to apply specific attributes to the deployment templates.

## What else do I need to know?
The Colonizer started its life as a downstream project with a specific intention, but it became clear that the community could benefit from and enhance the toolset for much broader application. As the original target use case involved only *Red Hat Gluster Storage*, a number of assumptions are made in the current code about the state of the systems and the network prior to running the Colonizer, not all of which are documented here (yet).

*Use the Gluster Colonizer at your own risk and with no implied warranty. There is a very good chance it will break your environment, delete your data, and eat whatever is in your fridge without even saying thank you.*

## Setup

### Requirements and Assumptions
This is initialy built for **Red Hat Gluster Storage 3.3.1** using the direct-install ISO. I expect right now for any other installation method that things will be very broken. Very. Care to fix it? Send me a pull request!

At install time, all optional packages are selected (NFS-Ganesha, Samba, AD Integration). We also add and enable NetworkManager (which for some inexplicable reason is included in the ISO but not directly available for install via the UI).

The **`gluster-colonizer.py`** script and all supporting config files and playbooks are copied into the `/root/g1 directory`.

The nodes should have a management network that is separate from the storage/production network. This network needs to allow mDNS (multicast DNS).

The nodes' management network interfaces are configured on a boot time with BOOTPROTO="none" in the ifcfg file, and a special systemd service enables a long-running dhcp client on the management interface.

### Deployment
Once the above is all taken care of and the nodes are booted and have active ethernet connections on the management network (assumed in the example configs currently to be eth0 -- modify as needed), you can make a console connection to _any one_ of the Gluster nodes and begin the deployment with the `gluster-colonizer.py` script.

### Dependencies
* Ansible modules from gdeploy [https://github.com/gluster/gdeploy]
* Gluster-zeroconf [https://github.com/gluster/gluster-zeroconf]
* Avahi

## TODOs
There are tons of them. Check the TODO tags in the code and the issues in Github.

## Known Bugs/Problems
* Using distributed-replicated volumes with arbiters will likely break if there is more than one data brick per host
