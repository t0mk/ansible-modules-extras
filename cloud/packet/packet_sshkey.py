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
import uuid


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
    sshkey_data = {}
    copy_keys = ['id', 'key', 'label','fingerprint']
    for name in copy_keys:
        sshkey_data[name] = getattr(sshkey, name)
    return sshkey_data


def _is_valid_uuid(myuuid):
    try:
        val = uuid.UUID(myuuid, version=4)
    except ValueError:
        return False
    return str(val) == myuuid


def get_existing_sshkeys(module, packet_conn): 
    return packet_conn.list_ssh_keys()

def load_key_file(filename):
    ret_dict = {}
    key_file_str = open(filename).read().strip()
    ret_dict['key'] = key_file_str
    cut_key = key_file_str.strip().split()
    if len(cut_key) in [2,3]:
        if len(cut_key) == 3:
            ret_dict['label'] = cut_key[2]
    else:
        raise Exception("Public key file %s is in wrong format" % filename)
    return ret_dict
    

def get_sshkey_selector(module):
    selecting_fields = ['label', 'fingerprint', 'id', 'key']
    key_id = module.params.get('id')
    if key_id:
        if not _is_valid_uuid(key_id):
            raise Exception("sshkey ID %s is not valid UUID" % key_id)

    select_dict = {f: module.params.get(f) for f in selecting_fields 
                   if module.params.get(f)}

    if module.params.get('key_file'):
        loaded_key = load_key_file(module.params.get('key_file'))
        select_dict['key'] = loaded_key['key']
        if module.params.get('label') is None:
            if loaded_key.get('label'):
                select_dict['label'] = loaded_key['label']

    def selector(k):
        if 'key' in select_dict:
             return k.key == select_dict['key']
        else:
             return all([select_dict[f] == getattr(k,f) for f in select_dict])
    return selector


def act_on_sshkeys(target_state, module, packet_conn):
    selector = get_sshkey_selector(module)
    existing_sshkeys = get_existing_sshkeys(module, packet_conn)
    matching_sshkeys = filter(selector, existing_sshkeys)
    #[k for k in existing_sshkeys if selector(k)]
    if target_state == 'present':
        if matching_sshkeys == []:
            # there is no key matching the fields from module call
            # => create the key, label and
            newkey = {}
            if module.params.get('key_file'):
                newkey = load_key_file(module.params.get('key_file'))
            for param in ('label', 'key'):
                if module.params.get(param):
                    newkey[param] = module.params.get(param)
            for param in ('label', 'key'):
                if param not in newkey:
                    _msg="you must supply either key_file OR (label AND key)"
                    raise Exception(_msg)
            matching_sshkeys = []
            new_key_response = packet_conn.create_ssh_key(
                                        newkey['label'], newkey['key'])
                              
            matching_sshkeys.append(new_key_response)
        else:
            # There's already a key matching the fields in the module call
            # => do nothing, and return {changed: False}
            matching_sshkeys = []
    else:
        # state is 'absent' => delete mathcing keys
        for k in matching_sshkeys:
            try:
                k.delete()
            except Exception as e:
                _msg = ("while trying to remove sshkey %s, id %s %s, "
                        "got error: %s" %
                       (k.label, k.id, target_state, e.message))
                raise Exception(_msg)

    return {
        'changed': True if matching_sshkeys else False,
        'sshkeys': [ _serialize_sshkey(k) for k in matching_sshkeys ]
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state = dict(choices=['present', 'absent'], default='present'),
            auth_token=dict(default=os.environ.get(PACKET_API_TOKEN_ENV_VAR)),
            label=dict(type='str', aliases=['name'], default=None),
            id=dict(type='str', default=None),
            fingerprint=dict(type='str', default=None),
            key=dict(type='str', default=None),
            key_file=dict(type='path', default=None),
        ),
        required_one_of=[('label','id',)],
        mutually_exclusive=[
            ('label', 'id'),
            ('label', 'fingerprint'),
            ('id', 'fingerprint'),
            ('key', 'fingerprint'),
            ('key', 'id'),
            ('key_file', 'key'),
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

    if state in ['present','absent']:
        try:
            module.exit_json(**act_on_sshkeys(state, module, packet_conn))
        except Exception as e:
            module.fail_json(msg='failed to set sshkey state: %s' % str(e))
    else:
        module.fail_json(msg='%s is not a valid state for this module' % state)


from ansible.module_utils.basic import * # noqa: F403


if __name__ == '__main__':
    main()
