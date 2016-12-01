#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: packet_sshkey
'''

EXAMPLES = '''

# Provisioning example. This will create three servers and enumerate their names.

'''


import os
import time
import uuid
import re


# debugging stuff, this should be at least commented in the PR
import logging
logging.basicConfig(filename='/tmp/plog',level=logging.DEBUG,
    format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')


HAS_PACKET_SDK = True


try:
    import packet
except ImportError:
    HAS_PACKET_SDK = False


# API is documented at
# https://www.packet.net/help/api/#page:ssh-keys,header:ssh-keys-ssh-keys-post

PACKET_API_TOKEN_ENV_VAR = "PACKET_API_TOKEN"

def _serialize_sshkey(sshkey):
    pass
    return sshkey_data


def _is_valid_uuid(myuuid):
    try:
        val = uuid.UUID(myuuid, version=4)
    except ValueError:
        return False
    return str(val) == myuuid


def create_devices(module, packet_conn):
    """
    Create new device

    module : AnsibleModule object
    packet_conn: authenticated packet object

    """
    project_id = module.params.get('project_id')
    wait = module.params.get('wait')
    wait_timeout = module.params.get('wait_timeout')
    logging.debug(module.params)
    logging.debug(module.params.get('count_offset'))
    hostname_list = _get_hostname_list(module)

    existing_devices =  get_existing_devices(module, packet_conn)
    existing_devices_names = [ed.hostname for ed in existing_devices]
    
    to_be_created_hostnames = [hn for hn in hostname_list if hn not in 
                               existing_devices_names]

    logging.debug(hostname_list)
    logging.debug(to_be_created_hostnames)

    created_devices = [_create_device(module, packet_conn, project_id, n)
                        for n in to_be_created_hostnames]


    def has_public_ip(addr_list):
        #logging.debug("has_pub_ip")
        #logging.debug(str(addr_list))
        return any([a['public'] and (len(a['address']) > 0) for a in addr_list])

    def all_have_public_ip(ds):
        #logging.debug("All_have_pu")
        #logging.debug(str(ds))
        return all([has_public_ip(d.ip_addresses) for d in ds])

    def refresh_created_devices(ids_of_created_devices, module, packet_conn):
        new_device_list = get_existing_devices(module, packet_conn)
        return [d for d in new_device_list if d.id in ids_of_created_devices]

    if wait:
        created_ids = [d.id for d in created_devices]
        wait_timeout = time.time() + wait_timeout
        while wait_timeout > time.time():
            refreshed = refresh_created_devices(created_ids, module,
                                                packet_conn)
            if all_have_public_ip(refreshed):
                indeed_created_devices = refreshed
                break
            time.sleep(5)
    else:
        indeed_created_devices = created_devices

    return {
        'changed': True if to_be_created_hostnames else False,
        'devices': [ _serialize_device(d) for d in indeed_created_devices],
    }


def get_existing_sshkeys(module, packet_conn): 
    return packet_conn.list_ssh_keys()


def get_sshkey_selector(module):
    selecting_fields = ['label', 'fingerprint', 'id', 'key']
    select_dict = {f: module.params.get(f) if module.params.get(f)}
    return lambda k: all([select_dict[f] == getattr(k,f)
                          for f in select_dict.keys()])

STATE_MAP = {
    'present': 
}


def act_on_sshkeys(target_state, module, packet_conn):
    selector = get_sshkey_selector(module)
    existing_sshkeys = get_existing_sshkeys(module, packet_conn)
    sshkeys_to_process  = [k for k in existing_sshkeys if selector(k)]
    if target_state == 'present':
        if sshkeys_to_process == []:
            # there is no key matching the fields from module call
            sshkeys_to_process = []
        else:
            # There's already a key matching the fields in the module call
            # => do nothing, and return {changed: False}
            sshkeys_to_process = []
    else:

    for k in sshkeys_to_process:
        api_operation = STATE_MAP[target_state]
        try:
            api_operation(d)
        except Exception as e:
            _msg = ("while trying to make device %s, id %s %s, from state %s, "
                    "got error: %s" %
                   (d.hostname, d.id, target_state, d.state, e.message))
            raise Exception(_msg)

    return {
        'changed': True if sshkeys_to_process else False,
        'sshkeys': [ _serialize_sshkey(d) for d in sshkeys_to_process ]
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            auth_token=dict(default=os.environ.get(PACKET_API_TOKEN_ENV_VAR)),
            label=dict(type='str', aliases=['name'], default=None),
            id=dict(type='str', default=None),
            fingerprint=dict(type='str', default=None),
            key=dict(type='str', default=None),
        ),
        required_one_of=[('label','id',)],
        mutually_exclusive=[
            ('label', 'id'),
            ('label', 'fingerprint'),
            ('id', 'fingerprint'),
            ('key', 'fingerprint'),
            ('key', 'id'),
            ]
    )

    if not HAS_PACKET_SDK:
        module.fail_json(msg='packet required for this module')

    if not module.params.get('auth_token'):
        _fail_msg = ( "if Packet API token is not in environment variable %s, "
                      "the auth_token parameter is required" % 
                       PACKET_API_TOKEN_ENV_VAR)
        module.fail_json(msg=_fail_msg)

    auth_token = module.params.get('auth_token')

    packet_conn = packet.Manager(auth_token=auth_token)

    state = module.params.get('state')

    if state == 'present':
        for param in ('label', 'key'):
            if not module.params.get(param):
                module.fail_json(
                    msg="%s parameter is required for new sshkey." % param)
    try:
        module.exit_json(**act_on_sshkey(state, module, packet_conn))
    except Exception as e:
        module.fail_json(msg='failed to set sshkey state: %s' % str(e))

from ansible.module_utils.basic import * # noqa: F403

if __name__ == '__main__':
    main()
