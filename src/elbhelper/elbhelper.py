#  Copyright 2015 Palo Alto Networks, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

__author__ = 'ivanbojer'
__version__ = ''

import logging
import socket

import ansible.runner
import ansible.playbook
from ansible.inventory import Inventory
from ansible import callbacks

import config.defaults as CFG
from db.dbdriver import FileDB

# logging facility
LOG = logging.getLogger(__name__)


def resolve_elb_name():
    elb_dns = CFG.ELB_DNS
    hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(elb_dns)

    return ipaddrlist


def find_changes():
    """find and write changes from the last poll"""
    ip_addrs = sorted(resolve_elb_name())
    if CFG.DEBUG:
        ip_addrs = ['10.0.1.95', '10.0.10.133', '10.0.10.118']
        ip_addrs = sorted(ip_addrs)

    saved_addrs = db.get_elb_addrs()

    removed_addrs = set(saved_addrs).difference(ip_addrs)
    new_addrs = set(ip_addrs).difference(saved_addrs)

    # check for removed addresses
    for address in removed_addrs:
        LOG.info('Address %s is not in DNS record anymore', address)
        fw_addr = find_fw_for_addr(address)

        db.del_address(address)

        if fw_addr is None: LOG.warn("Could not find home firewall for removed address %s", address)

    # check for new addresses
    for address in new_addrs:
        LOG.info('New address %s', address)
        fw_addr = find_fw_for_addr(address)

        db.add_address(address, fw_addr)

        if fw_addr is None: LOG.warn("Could not find home firewall for new address %s", address)

    ip_changed = False
    if len(removed_addrs) != 0 or len(new_addrs) != 0:
        ip_changed = True

    return ip_changed, removed_addrs, new_addrs


def find_fw_for_addr(ip):
    """
    Based on the default.py configuration file this function will try to find which firewalls
    can server given IP
    :param ip:
    :return:
    """
    for az in CFG.AZ_PREFIX_MAP:
        az_ip = CFG.AZ_PREFIX_MAP[az]
        if az_ip in ip:
            fw_ip = __get_firewall_for_az(az)
            return fw_ip

    return None


def update_firewalls(removed_addres_set, new_addres_set):
    """
    Try to 'smart-update' firewalls based on the changed IPs.
    The logic here is:
        #1 if ELB IP was removed
           - check if IP was assigned to a firewall
               - if not, do nothing
               - if yes, reassign another IP to the firewall
       #2 if ELB IP was added
           - figure out if there is available firewall that can server it
       #3 if ELB IP was both removed and added
           - go back through #1

    :param removed_addres_set:
    :param new_addres_set:
    :return:
    """
    is_addr_removed = len(removed_addres_set) > 0
    is_addr_added = len(new_addres_set) > 0

    if is_addr_removed and not is_addr_added:
        LOG.info('CASEOF: address removed')
        handle_removed_addrs(removed_addres_set)
    elif not is_addr_removed and is_addr_added:
        LOG.info('CASEOF: address added')
        handle_added_addrs(new_addres_set)
    elif is_addr_removed and is_addr_added:
        LOG.info('CASEOF: address removed and added')
        handle_removed_addrs(removed_addres_set)
        handle_added_addrs(new_addres_set)


def handle_removed_addrs(removed_addr_set):
    """Handle removed addresses"""
    for removed_addr in removed_addr_set:
            success, fw_addr = __reallocate_fw_address(removed_addr)
            if success:
                LOG.info('Reallocated %s to firewall %s', removed_addr, fw_addr)
            else:
                LOG.warn('Could not reallocate %s (no free firewalls?)', removed_addr)


def handle_added_addrs(new_addres_set):
    """Handle added addresses"""
    for added_addr in new_addres_set:
        # check if we have firewall that can server this address
        fw_addr = find_fw_for_addr(added_addr)
        if fw_addr is None:
            LOG.warn('DNS address %s cannot be served. Cannot find applicable firewall.', added_addr)
        else:
            # check if firewall is already occupied
            if db.is_fw_occupied(fw_addr):
                LOG.warn('DNS address %s cannot be served. No free firewalls.', added_addr)
            else:
                success = update_fw_nat_rule(fw_addr, added_addr)
                if success:
                    db.add_assignement(fw_addr, added_addr)
                    LOG.info('DNS address %s now served by %s', fw_addr, added_addr)


def update_fw_nat_rule(fw_ip, elb_ip):
    """
    Call our trivial playbook in order to upgrade firewall rules
    :param fw_ip:
    :param elb_ip:
    :return bool, String success state and the corresponding message:
    """

    if CFG.DEBUG:
        return True, 'DUMMY Works!'

    extra_vars = {
        'host': fw_ip,
        'admin_password': CFG.FW_PWD,
        'elb_ip': elb_ip
    }

    inventory = Inventory(host_list="localhost,127.0.0.1")
    stats = callbacks.AggregateStats()
    playbook_cb = callbacks.PlaybookCallbacks(verbose=CFG.VERBOSE)
    runner_cb = callbacks.PlaybookRunnerCallbacks(stats, verbose=CFG.VERBOSE)
    #
    module_path= CFG.ANSIBLE_LIBRARY
    # module_path = '/library'

    # construct the ansible runner and execute on all hosts
    pb = ansible.playbook.PlayBook(
        playbook=CFG.PLAYBOOK,
        module_path=module_path,
        stats=stats,
        inventory=inventory,
        callbacks=playbook_cb,
        runner_callbacks=runner_cb,
        extra_vars=extra_vars
    )

    results = pb.run()

    if len(pb.stats.dark) != 0:
        return False, "Ansible: Unreachable"
    if len(pb.stats.failures) != 0:
        return False, "Ansible: Playbook failed"

    return True, 'Attempted updating firewall {} with NAT address of {}'.format(fw_ip, elb_ip)


def __reallocate_fw_address(removed_addr, added_addrs=None):
    # check if on of the removed address belonged to a firewall
    fw_addr_assigned = db.get_assigned_fw(removed_addr)

    # no firewall was assigned to this ip so no loss
    if not fw_addr_assigned:
        LOG.info('address %s was removed but it was not assigned to a firwall (NOOP)', removed_addr)
        return
    else:
        LOG.info('address %s was removed AND it was assigned to a firwall %s', removed_addr, fw_addr_assigned)
        # update the database by removing FW from the assignements
        db.del_assignement(fw_addr_assigned)

        # lets find assigned addresses
        assigned_addr = db.get_assigned_addresses()
        # lets find all ELB addresses
        elb_addr = db.get_elb_addrs()
        # let find difference that will allow us to find unassigned addresses
        unassigned_addresses = set(elb_addr).difference(assigned_addr)

        success = False
        msg = None
        for unassigned_addr in unassigned_addresses:
            fw_addr = find_fw_for_addr(unassigned_addr)

            # determine if our firewall that just lost the address works for this addr
            # this should alway evaluate to true in case of 1:1 FW to IP mapping
            # but it can be handy if and when we can assign more than one address
            # to the firwall NAT rule
            if not db.is_fw_occupied(fw_addr):
                if update_fw_nat_rule(fw_addr, unassigned_addr):
                    db.add_address(unassigned_addr, fw_addr)
                    db.add_assignement(fw_addr, unassigned_addr)
                    success = True
                    if msg is None:
                        msg = ''
                    msg += fw_addr

        return success, msg


def __get_firewall_for_az(az):
    """
    Return the list of firwalls that can serve give az
    :param az:
    :return String ip of the firewall that can server given az:
    """
    fws = CFG.FIREWALLS
    for fw_key in fws.keys():
        if fws[fw_key] in az:
            return fw_key

    return None

if __name__ == "__main__":
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y%m%d %T',
        level=logging.DEBUG)
    logging.getLogger('boto').setLevel(logging.ERROR)

    db = FileDB(CFG.DB_FILE)

    import time, sys
    counter = 0
    while True:

        counter += 1

        try:
            is_changed, removed_addrs, new_addrs = find_changes()
            if is_changed:
                LOG.info('ELB address changed, updating firewall rules [check #%s]', counter)
                update_firewalls(removed_addrs, new_addrs)
            else:
                LOG.info('ELB address did not change [check #%s]. Nothing to do!', counter)

            # if not CFG.DEBUG:
            #     if CFG.SLEEP < 60:
            #         LOG.warn('Retry time cannot be less than 60 seconds.')
            #         sys.exit(0)
            time.sleep(CFG.SLEEP)
        except KeyboardInterrupt:
            LOG.info("Good bye!")
            sys.exit(0)
