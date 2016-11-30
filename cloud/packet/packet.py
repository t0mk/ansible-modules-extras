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
module: packet
short_description: create, destroy, start, stop, and reboot a Packet Host machine.
description:
     - create, destroy, update, start, stop, and reboot a Packet Host machine. When the machine is created it can optionally wait for it to be 'running' before returning. This module has a dependency on packet >= 1.0
version_added: "2.1"
options:
  state:
    description:
      - Define a device's state to create, remove, start or stop it.
    required: false
    default: 'present'
    choices: [ "present", "absent", "running", "stopped" ]
  project_id:
    description:
      - Your Packet Project ID.
    required: true
  auth_token:
    description:
      - Authenticating API token provided by Packet.
    required: true
  hostnames:
    description:
      - The hostname or ID of the device. Only used when state is 'present'.
    required: true when state is 'present', false otherwise.
  operating_system:
    description:
      - The system operating_system name for creating the machine, e.g. coreos_stable.
    required: true for 'present' state, false otherwise
  plan:
    description:
      - Plan to use for this device.
    required: true for 'present' state, false otherwise
    choices: [ "baremetal_0", "baremetal_1", "baremetal_3" ]
  facility:
    description:
      - The datacenter location.
    required: false
    default: ewr1
    choices: [ "ewr1" ]
  device_ids:
    description:
      - list of device ids or host names, used when state is 'running', 'stopped' or 'absent'.
    required: false for 'running' state, true otherwise
  count:
    description:
      - The number of machines to create.
    required: false
    default: 1
  locked:
    description:
      - Whether to lock the device. If not specified, the lock state will not be changed.
    required: false
    default: null
    choices: [ "yes", "no", null ]
  user_data:
    description:
      - opaque blob of data which is made available to the machine
    required: false
    default: None
  wait:
    description:
      - wait for the instance to be in state 'running' before returning
    required: false
    default: "yes"
    choices: [ "yes", "no" ]
  wait_timeout:
    description:
      - how long before wait gives up, in seconds
    default: 600
  auto_increment:
    description:
      - When creating multiple devices at once, whether to differentiate hostnames by appending a count after them or substituting the count where there is a %02d or %03d in the hostname string.
    default: yes
    choices: ["yes", "no"]

requirements:
     - "packet"
     - "python >= 2.6"
author: Matt Baldwin (baldwin@stackpointcloud.com)
'''

EXAMPLES = '''

# Provisioning example. This will create three servers and enumerate their names.

- packet:
    project_id: StackPointCloud
    auth_token: packet_private_api_key
    name: node%02d.stackpointcloud.com
    plan: baremetal_1
    facility: ewr1
    operating_system: coreos_stable
    count: 3

# Create three machines, passing in user_data.

- packet:
    project_id: StackPointCloud
    auth_token: packet_private_api_key
    name: node%02d.stackpointcloud.com
    plan: baremetal_1
    facility: ewr1
    operating_system: coreos_stable
    count: 3
    wait: yes
    wait_timeout: 600
    user_data: |
      #cloud-config
      ssh_authorized_keys:
        - "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0g+ZTxC7weoIJLUafOgrm+h..."

      coreos:
        etcd:
          # generate a new token for each unique cluster from https://discovery.etcd.io/new
          discovery: https://discovery.etcd.io/{{ discovery_token }}
          # use $public_ipv4 if your datacenter of choice does not support private networking
          addr: $private_ipv4:4001
          peer-addr: $private_ipv4:7001
        fleet:
          public-ip: $private_ipv4   # used for fleetctl ssh command
        units:
          - name: etcd.service
            command: start
          - name: fleet.service
            command: start

# Removing machines

- packet:
    project_id: StackPointCloud
    auth_token: packet_private_api_key
    state: absent
    device_ids:
      - 'node01.stackpointcloud.com'
      - 'node02.stackpointcloud.com'
      - 'node03.stackpointcloud.com'

# Starting Machines.

- packet:
    project_id: StackPointCloud
    auth_token: packet_private_api_key
    state: running
    device_ids:
      - 'node01.stackpointcloud.com'
      - 'node02.stackpointcloud.com'
      - 'node03.stackpointcloud.com'

# Stopping Machines

- packet:
    project_id: StackPointCloud
    auth_token: packet_private_api_key
    state: stopped
    device_ids:
      - 'node01.stackpointcloud.com'
      - 'node02.stackpointcloud.com'
      - 'node03.stackpointcloud.com'

# Lock a pachine
- packet:
    project_id: StackPointCloud
    auth_token: packet_private_api_key
    state: running
    locked: yes
    device_ids:
      - 'node01.stackpointcloud.com'
      - 'node02.stackpointcloud.com'
      - 'node03.stackpointcloud.com'

'''

RETURN = '''
changed:
    description: True if a device was altered in any way (created, modified or removed)
    type: bool
    sample: True
    returned: always
devices:
    description: Information about each device that was processed
    type: array
    sample: '[{"hostname": "my-server.com", "id": "server-id"}]'
    returned: always
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
# https://www.packet.net/help/api/#page:devices,header:devices-devices-post

_NAME_RE = '({0}|{0}{1}*{0})'.format('[a-zA-Z0-9]','[a-zA-Z0-9\-]')
HOSTNAME_RE = '({0}\.)*{0}$'.format(_NAME_RE)
MAX_DEVICES = 100

PACKET_DEVICE_STATES = (
    'queued',
    'provisioning',
    'failed',
    'powering_on',
    'active',
    'powering_off',
    'inactive',
    'rebooting',
)

PACKET_API_TOKEN_ENV_VAR = "PACKET_API_TOKEN"


def _serialize_device(device):
    """
    Standard represenation for a device as returned by various tasks::

        {
            'id': 'device_id'
            'hostname': 'device_hostname',
            'tags': [],
            'locked': false,
            'ip_addresses': [
                {
                    "address": "147.75.194.227",
                    "address_family": 4,
                    "public": true
                },
                {
                    "address": "2604:1380:2:5200::3",
                    "address_family": 6,
                    "public": true
                },
                {
                    "address": "10.100.11.129",
                    "address_family": 4,
                    "public": false
                }
            ],
            "private_ipv4": "10.100.11.129",
            "public_ipv4": "147.75.194.227",
            "public_ipv6": "2604:1380:2:5200::3",
        }

    """
    device_data = {}
    device_data['id'] = device.id
    device_data['hostname'] = device.hostname
    device_data['tags'] = device.tags
    device_data['locked'] = device.locked
    device_data['ip_addresses'] = [
        {
            'address': addr_data['address'],
            'address_family': addr_data['address_family'],
            'public': addr_data['public'],
        }
        for addr_data in device.ip_addresses
    ]
    # Also include each IPs as a key for easier lookup in roles.
    # Key names:
    # - public_ipv4
    # - public_ipv6
    # - private_ipv4
    # - private_ipv6 (if there is one)
    for ipdata in device_data['ip_addresses']:
        if ipdata['public']:
            if ipdata['address_family'] == 6:
                device_data['public_ipv6'] = ipdata['address']
            elif ipdata['address_family'] == 4:
                device_data['public_ipv4'] = ipdata['address']
        elif not ipdata['public']:
            if ipdata['address_family'] == 6:
                # Packet doesn't give public ipv6 yet, but maybe one
                # day they will
                device_data['private_ipv6'] = ipdata['address']
            elif ipdata['address_family'] == 4:
                device_data['private_ipv4'] = ipdata['address']
    return device_data


def _is_valid_hostname(hostname):
    return re.match(HOSTNAME_RE, hostname) is not None


def _is_valid_uuid(myuuid):
    try:
        val = uuid.UUID(myuuid, version=4)
    except ValueError:
        return False
    return str(val) == myuuid


def _listify_string_name_or_id(s):
    if ',' is s:
        return [i.strip() for i in s.split(',')]
    else:
        return [s.strip()]


def _has_int_formatter(s):
    if re.search("%\d{0,2}d", s):
        return True
    else:
        return False


def _get_hostname_list(module):
    # hostname is a list-typed param, so I guess it should return list
    # (and it does, in Ansbile 2.2.1) but in order to be defensive,
    # I keep here the code to convert an eventual string to list
    hostnames = module.params.get('hostnames')
    count = module.params.get('count')
    count_offset = module.params.get('count_offset')
    if isinstance(hostnames, str):
        hostnames = _listify_string_name_or_id(hostnames)
    if not isinstance(hostnames, list):
        raise Exception("name %s is not convertible to list" % hostnames)

    # at this point, hostnames is a list
    hostnames = [h.strip() for h in hostnames]

    if (len(hostnames) > 1) and (count > 1):
        _msg = ("If you set count>1, you should only specify one hostname "
                "with the %d formatter, not a list of hostnames.")
        raise Exception(_msg)
        
    if (len(hostnames) == 1) and (count > 0):
        hostname_spec = hostnames[0]
        count_range = range(count_offset, count_offset + count)
        if _has_int_formatter(hostname_spec):
            hostnames = [hostname_spec % i for i in count_range]
        elif count > 1:
            hostname_spec = '%s%%02d' % hostname_spec
            hostnames = [hostname_spec % i for i in count_range]

    logging.debug(hostnames)
    logging.debug(type(hostnames))

    for hn in hostnames:
        if not _is_valid_hostname(hn):
            raise Exception("Hostname '%s' does not seem to be valid" % hn)

    if len(hostnames) > MAX_DEVICES:
        raise Exception("You specified too many devices, max is %d" %
                         MAX_DEVICES)
    return hostnames


def _get_device_id_list(module):
    device_ids = module.params.get('device_ids')

    if isinstance(device_ids, str):
        device_ids = _listify_string_name_or_id(device_ids)

    device_ids = [di.strip() for di in device_ids]

    logging.debug(device_ids)
    # trtying to be ultra user-friednly 
    for di in device_ids:
        if not _is_valid_uuid(di):
            raise Exception("Device ID '%s' does not seem to be valid" % di)

    if len(device_ids) > MAX_DEVICES:
        raise Exception("You specified too many devices, max is %d" %
                         MAX_DEVICES)
    return device_ids
     

def _create_device(module, packet_conn, project_id, hostname):
    plan = module.params.get('plan')
    user_data = module.params.get('user_data')
    facility = module.params.get('facility')
    operating_system = module.params.get('operating_system')
    locked = module.params.get('locked')

    device = packet_conn.create_device(
        project_id=project_id,
        hostname=hostname,
        plan=plan,
        facility=facility,
        operating_system=operating_system,
        userdata=user_data,
        locked=locked)
    return device


def create_devices(module, packet_conn):
    """
    Create new device

    module : AnsibleModule object
    packet_conn: authenticated packet object

    Returns a dictionary containing a 'changed' attribute indicating whether
    any device was added, and a 'devices' attribute with the list of the
    created devices's hostname, id and ip addresses.
    """
    project_id = module.params.get('project_id')
    wait_for_ips = module.params.get('wait_for_ips')
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
        return any([a['public'] and len(a['address'] > 0) for a in addr_list])
    def all_have_public_ips(ds):
        return all([has_public_ip(d.ip_addresses) for d in ds])
                 
    if wait_for_ips:
        renewed_device_list = get_existing_devices(module, packet_conn)
        wait_timeout = time.time() + wait_timeout
        while wait_timeout > time.time():
            refreshed_created_devices = [d for d in created_devices
                if d.id in [rdl_dev.id for rdl_dev in renewed_device_list]]
            if all_have_public_ips(refreshed_created_devices):
                indeed_created_devices = refreshed_created_devices
                break
            time.sleep(5)
            renewed_device_list = get_existing_devices(module, packet_conn)
    else:
        indeed_created_devices = created_devices

    return {
        'changed': True if to_be_created_hostnames else False,
        'devices': [ _serialize_device(d) for d in indeed_created_devices],
    }



DESIRED_STATE_MAP = {
    'absent': {k: lambda d: d.delete() for k in PACKET_DEVICE_STATES},
    'active': {'inactive': lambda d: d.power_on()},
    'inactive': {'active': lambda d: d.power_off(),
                 'nonexistent': _create_device},
    'rebooted': {'active': lambda d: d.reboot(),
                 'inactive': lambda d: d.power_on()}
    }


def get_device_selector(module):
    if module.params.get('device_ids'):
        device_id_list = _get_device_id_list(module)
        return lambda d: d.id in device_id_list
    elif module.params.get('hostnames'):
        hostname_list = _get_hostname_list(module)
        return lambda d: d.hostname in hostname_list


def get_existing_devices(module, packet_conn): 
    project_id = module.params.get('project_id')
    return packet_conn.list_devices(project_id,
                                         params={'per_page': MAX_DEVICES})


def act_on_devices(target_state, module, packet_conn):
    selector = get_device_selector(module)
    existing_devices = get_existing_devices(module, packet_conn)
    devices_to_process  = [d for d in existing_devices if selector(d) and
                           d.state in DESIRED_STATE_MAP[target_state]]
    for d in devices_to_process:
        api_operation = DESIRED_STATE_MAP[target_state][d.state]
        try:
            api_operation(d)
        except Exception as e:
            _msg = ("while trying to make device %s, id %s %s, from state %s, "
                    "got error: %s" %
                   (d.hostname, d.id, target_state, d.state, e.message))
            raise Exception(_msg)

    return {
        'changed': True if devices_to_process else False,
        'devices': [ _serialize_device(d) for d in devices_to_process ]
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            project_id=dict(required=True),
            hostnames=dict(type='list', aliases=['name']),
            operating_system=dict(),
            plan=dict(),
            count=dict(type='int', default=1),
            count_offset=dict(type='int', default=1),
            user_data=dict(default=None),
            device_ids=dict(type='list'),
            features=dict(),
            locked=dict(type='bool', default=False),
            auth_token=dict(default=os.environ.get(PACKET_API_TOKEN_ENV_VAR)),
            facility=dict(default='ewr1'),
            state=dict(default='present'),
            wait_for_ips=dict(type='bool', default=False),
            wait_timeout=dict(type='int', default=60),

        ),
        required_one_of=[('device_ids','hostnames',)],
        mutually_exclusive=[
            ('hostnames', 'device_ids'),
            ('count', 'device_ids'),
            ('count_offset', 'device_ids'),
            ]
    )

    if not HAS_PACKET_SDK:
        module.fail_json(msg='packet required for this module')

    if not module.params.get('project_id'):
        module.fail_json(
            msg='project_id parameter is required.')

    if not module.params.get('auth_token'):
        _fail_msg = ( "if Packet API token is not in environment variable %s, "
                      "the auth_token parameter is required" % 
                       PACKET_API_TOKEN_ENV_VAR)
        module.fail_json(msg=_fail_msg)

    auth_token = module.params.get('auth_token')

    packet_conn = packet.Manager(auth_token=auth_token)

    state = module.params.get('state')

    if state in ('running', 'stopped', 'rebooted','absent'):
        try:
            module.exit_json(**act_on_devices(state, module, packet_conn))
        except Exception as e:
            module.fail_json(msg='failed to set machine state: %s' % str(e))

    elif state == 'present':
        for param in ('hostnames', 'operating_system', 'plan'):
            if not module.params.get(param):
                module.fail_json(
                    msg="%s parameter is required for new instance." % param)
        try:
            module.exit_json(**create_devices(module, packet_conn))
        except Exception as e:
            module.fail_json(msg='failed when creating device(s): %s' % str(e))

from ansible.module_utils.basic import * # noqa: F403

if __name__ == '__main__':
    main()
