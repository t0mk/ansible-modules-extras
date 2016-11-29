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

# debugging stuff, this should be at least commented in the PR
import logging
logging.basicConfig(filename='/tmp/plog',level=logging.DEBUG,
    format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')


HAS_PACKET_SDK = True

try:
    import packet
except ImportError:
    HAS_PACKET_SDK = False

# Enums for certain parameters for the API, documented at
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

#def _find_project(packet_conn, project_id):
#    """
#    Given a project_id, validates that the project exists whether it is
#    a proper ID or a name. If the project cannot be found, return None.
#   """
#    project = None
#    for _project in packet_conn.list_projects():
#        if project_id in (_project.id, _project.name):
#            project = _project
#            break
#    return project


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


def _expand_hostname_specification(module):
    hostname_spec = module.params.get('hostnames')
    count = module.params.get('count')
    if count == 0:
        # this is the most basic case when "count" param is not specified,
        # and "hostnames" is not a list => it's just a single (hopefully valid)
        # hostname
        return [hostname_spec]
    
    count_offset = module.params.get('count_offset')
    # this cool try/except is copied over from core/cloud/rackspace/rax.py
    try:
        hostname_spec % 0
    except TypeError as e:
        if e.message.startswith('not all'):
            hostname_spec = '%s%%02d' % hostname_spec
        else:
            raise e
    return [hostname_spec % i for i in range(count_offset,count_offset + count)]


def _get_hostname_list(module):
    hostnames = module.params.get('hostnames')
    if isinstance(hostnames, list) and (len(hostnames) > 0) and (count > 0):
        _msg = ("If you have count>0, you should only specify one hostname "
                "with the %d formatter, not a list of hostnames.")
        raise Exception(_msg)

    logging.debug(hostnames)
    logging.debug(type(hostnames))
    if not isinstance(hostnames, list):
        # Once type='list' is specified in Ansible, the params should not be
        # anything else, but to be defensive, I keep this code here
        if "," in hostnames:
            hostnames = [h.strip() for h in hostnames.split(",")]
        else:
            hostnames = _expand_hostname_specification(module)
    #if (count > 0) and len(hostname) == 1:


    for hn in hostnames:
        if not _is_valid_hostname(hn):
            raise Exception("Hostname '%s' does not seem to be valid" 
                             % hn)

    if len(hostnames) > MAX_DEVICES:
        raise Exception("You specified too many devices, max is %d" %
                         MAX_DEVICES)
    return hostnames


def _get_device_id_list(module):
    device_ids = module.params.get('device_ids')

    if not isinstance(device_ids, list):
        if "," in device_ids:
            device_ids = [di.strip() for di in  device_ids.split(",")]
        else:
            device_ids = [device_ids]

    logging.debug(device_ids)
    # trtying to be ultra user-friednly 
    device_ids = [di.strip() for di in device_ids]
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
    logging.debug(module.params)
    logging.debug(module.params.get('count_offset'))
    #auto_increment = module.params.get('auto_increment')
    #wait = module.params.get('wait')
    #wait_timeout = module.params.get('wait_timeout')
    hostname_list = _get_hostname_list(module)

    existing_devices = packet_conn.list_devices(project_id,
        params={'per_page': MAX_DEVICES})
    existing_devices_names = [ed.hostname for ed in existing_devices]
    
    to_be_created_hostnames = [hn for hn in hostname_list if hn not in 
                               existing_devices_names]

    logging.debug(hostname_list)
    logging.debug(to_be_created_hostnames)
    for _hostname in to_be_created_hostnames:
        if not _is_valid_hostname(_hostname):
            raise Exception("Hostname \"%s\" does not seem to be valid" % _hostname)
    devices = [_create_device(module, packet_conn, project_id, n) for n in
               to_be_created_hostnames]

    return {
        'changed': True if to_be_created_hostnames else False,
        'devices': [ _serialize_device(device) for device in devices ],
    }


def remove_devices(module, packet_conn):
    """
    Remove devices.

    module : AnsibleModule object
    packet_conn: authenticated packet object.

    Returns a dictionary containing a 'changed' attribute indicating whether
    any devices were removed, and a 'devices' attribute with the list of the
    removed devices's hostname and id.
    """
    project_id = module.params.get('project_id')

    to_be_removed_devices = []
    using_ids = True
    if module.params.get('device_ids'):
        device_id_list = _get_device_id_list(module)
    elif module.params.get('hostnames'):
        using_ids = False
        hostname_list = _get_hostname_list(module)

    existing_devices = packet_conn.list_devices(project_id,
                                         params={'per_page': MAX_DEVICES})
    if using_ids:
        to_be_removed_devices = [d for d in existing_devices
                                 if d.id in device_id_list]
    else:
        to_be_removed_devices = [d for d in existing_devices
                                 if d.hostname in hostname_list]

    delete_responses = [d.delete() for d in to_be_removed_devices]

    return {
        'changed': True if delete_responses else False,
        'devices': [{
            'id': device.id,
            'hostname': device.hostname,
        } for device in to_be_removed_devices]
    }


def startstop_device(module, packet_conn):
    """
    Starts or Stops a device.

    module : AnsibleModule object
    packet_conn: authenticated packet object.

    Returns a dictionary with a 'changed' attribute indicating whether
    anything has changed for any of the devices as a result of this function
    being run, and a 'devices' attribute with basic information for
    each device.
    """
    state = module.params.get('state')
    project_id = module.params.get('project_id')
    device_ids = module.params.get('device_ids')
    wait = module.params.get('wait')
    wait_timeout = module.params.get('wait_timeout')
    locked = module.params.get('locked')

    if not isinstance(device_ids, list) or len(device_ids) < 1:
        module.fail_json(
            msg='device_ids should be a list of virtual machine ids or names.')

    # Find the project
    #project = _find_project(packet_conn, project_id)
    if project_id is None:
        module.fail_json(
            msg='project_id %s not found.' % module.params.get('project_id'))

    devices = []
    changed = False
    for device_id in device_ids:

        # Resolve device
        #device = _find_device(packet_conn, project_id, device_id)
        if device is None:
            continue

        # See if the device needs to be locked or unlocked
        if device.locked == True and locked == False:
            device.locked = False
            device.update()
            changed = True
        elif device.locked == False and locked == True:
            device.locked = True
            device.update()
            changed = True

        # Attempt to change the machine state, only if it's not already there
        # or on its way.
        try:
            if state == 'stopped':
                if device.state in ('powering_off', 'inactive'):
                    devices.append(device)
                    continue
                device.power_off()
            elif state == 'running':
                if device.state in ('powering_on', 'active'):
                    devices.append(device)
                    continue
                device.power_on()
        except Exception as e:
            module.fail_json(
                msg="failed to set device %s to state %s: %s" % (
                    device_id, state, str(e)))

        # Make sure the machine has reached the desired state
        if wait:
            operation_completed = False
            wait_timeout = time.time() + wait_timeout
            while wait_timeout > time.time():
                time.sleep(5)
                device = packet_conn.get_device(device.id)  # refresh
                if state == 'stopped' and device.state == 'inactive':
                    operation_completed = True
                    break
                if state == 'running' and device.state == 'active':
                    operation_completed = True
                    break
            if not operation_completed:
                module.fail_json(
                    msg="Timeout waiting for device %s to get to state %s" % (
                        device.id, state))

        changed = True
        devices.append(device)

    return {
        'changed': changed,
        'devices': [ _serialize_device(device) for device in devices ]
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            project_id=dict(required=True),
            hostnames=dict(type='list', aliases=['name']),
            operating_system=dict(),
            plan=dict(),
            count=dict(type='int', default=0),
            count_offset=dict(type='int', default=1),
            user_data=dict(default=None),
            #auto_increment=dict(type='bool', default=True),
            device_ids=dict(type='list'),
            features=dict(),
            locked=dict(type='bool', default=False),
            auth_token=dict(default=os.environ.get(PACKET_API_TOKEN_ENV_VAR)),
            facility=dict(default='ewr1'),
            state=dict(default='present'),
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

    if state == 'absent':
        try:
            module.exit_json(**remove_devices(module, packet_conn))
        except Exception as e:
            module.fail_json(msg='failed to set machine state: %s' % str(e))

    elif state in ('running', 'stopped'):
        try:
            module.exit_json(**startstop_device(module, packet_conn))
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
