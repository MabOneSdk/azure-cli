# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import time
import json

from msrest.exceptions import DeserializationError

from azure.mgmt.recoveryservices.models import Vault
from azure.mgmt.recoveryservicesbackup.models import ProtectedItemResource, AzureIaaSComputeVMProtectedItem

from azure.cli.core.util import CLIError
import azure.cli.core.azlogging as azlogging

from azure.cli.command_modules.backup._client_factory import (
    vm_mgmt_client_factory,
    policy_mgmt_client_factory,
    policies_mgmt_client_factory,
    containers_mgmt_client_factory,
    protectable_items_mgmt_client_factory,
    protected_items_mgmt_client_factory,
    items_mgmt_client_factory,
    protection_containers_mgmt_client_factory,
    backup_operation_statuses_mgmt_client_factory,
    refresh_operation_results_mgmt_client_factory)

logger = azlogging.get_az_logger(__name__)

def show_item(client, item_name, container, vault, workload_type="AzureVM"):
    items_client = items_mgmt_client_factory(None)
    
    rs_vault = get_vault_from_json(client, vault)
    resource_group = get_resource_group_from_id(rs_vault.id)
    container_object = get_container_from_json(items_client, container)

    filter_string = get_filter_string({
        'backupManagementType' : container_object.properties.backup_management_type,
        'itemType' : get_item_type(workload_type)})

    items = items_client.list(rs_vault.name, resource_group, filter_string)
    paged_items = get_paged_list(items)

    filtered_items = []
    for item in paged_items:
        if item.properties.container_name in container_object.name:
            if item.properties.friendly_name == item_name:
                filtered_items.append(item)

    return get_one_or_many(filtered_items)

def list_items(client, container, vault):
    items_client = items_mgmt_client_factory(None)
    
    rs_vault = get_vault_from_json(client, vault)
    resource_group = get_resource_group_from_id(rs_vault.id)
    container_object = get_container_from_json(items_client, container)

    filter_string = get_filter_string({
        'backupManagementType' : container_object.properties.backup_management_type})

    items = items_client.list(rs_vault.name, resource_group, filter_string)
    paged_items = get_paged_list(items)

    items_in_container = []
    for item in paged_items:
        if item.properties.container_name in container_object.name:
            items_in_container.append(item)

    return get_one_or_many(items_in_container)

def show_container(client, container_name, vault, container_type="AzureVM", status="Registered"):
    rs_vault = get_vault_from_json(client, vault)
    resource_group = get_resource_group_from_id(rs_vault.id)

    backup_management_type = get_backup_management_type(container_type)

    filter_string = get_filter_string({
        'friendlyName' : container_name,
        'backupManagementType' : backup_management_type,
        'status' : status})

    containers = containers_mgmt_client_factory(None).list(rs_vault.name, resource_group, filter_string)
    return get_one_or_many(get_paged_list(containers))

def list_containers(client, vault, container_type="AzureVM", status="Registered"):
    rs_vault = get_vault_from_json(client, vault)
    resource_group = get_resource_group_from_id(rs_vault.id)

    backup_management_type = get_backup_management_type(container_type)

    filter_string = get_filter_string({
        'backupManagementType' : backup_management_type, 
        'status' : status})

    containers = containers_mgmt_client_factory(None).list(rs_vault.name, resource_group, filter_string)
    return get_one_or_many(get_paged_list(containers))

def show_policy(client, policy_name, vault):
    rs_vault = get_vault_from_json(client, vault)
    resource_group = get_resource_group_from_id(rs_vault.id)

    policy = policy_mgmt_client_factory(None).get(rs_vault.name, resource_group, policy_name)
    return policy

def list_policies(client, vault):
    rs_vault = get_vault_from_json(client, vault)
    resource_group = get_resource_group_from_id(rs_vault.id)

    policies = policies_mgmt_client_factory(None).list(rs_vault.name, resource_group)
    return get_one_or_many(get_paged_list(policies))

def enable_protection_for_vm(client, vm, vault, policy):
    # Client factories
    policy_client = policy_mgmt_client_factory(None)
    protected_item_client = protected_items_mgmt_client_factory(None)
    protection_container_client = protection_containers_mgmt_client_factory(None)
    
    # Get objects from JSON files
    vm = get_vm_from_json(vm_mgmt_client_factory(None), vm)
    rs_vault = get_vault_from_json(client, vault)
    resource_group = get_resource_group_from_id(rs_vault.id)
    policy = get_policy_from_json(policy_client, policy)

    # VM name and resource group name
    vm_name = vm.name
    vm_rg = get_resource_group_from_id(vm.id)
    
    # Get protectable item.
    protectable_item = get_protectable_item(rs_vault.name, resource_group, vm_name, vm_rg)
    if protectable_item is None:
        raise CliError("""
The specified Azure Virtual Machine Not Found. Possible causes are
   1. VM does not exist
   2. The VM name or the Service name needs to be case sensitive
   3. VM is already Protected with same or other Vault. Please Unprotect VM first and then try to protect it again.
   
Please contact Microsoft for further assistance.
""")
    
    # Construct enable protection request object
    container_uri = get_protection_container_uri_from_id(protectable_item.id)
    item_uri = get_protectable_item_uri_from_id(protectable_item.id)    
    vm_item_properties = AzureIaaSComputeVMProtectedItem(policy_id=policy.id, source_resource_id=protectable_item.properties.virtual_machine_id)
    vm_item = ProtectedItemResource(properties=vm_item_properties)

    # Trigger enable protection and wait for completion
    result = protected_item_client.create_or_update(rs_vault.name, resource_group, "Azure", container_uri, item_uri, vm_item, raw=True)    
    wait_for_backup_operation(result, rs_vault.name, resource_group)

def disable_protection(client, backup_item, vault):
    # Client factories
    items_client = items_mgmt_client_factory(None)
    protected_item_client = protected_items_mgmt_client_factory(None)

    # Get objects from JSON files
    item = get_item_from_json(items_client, backup_item)
    rs_vault = get_vault_from_json(client, vault)
    resource_group = get_resource_group_from_id(rs_vault.id)

    # Construct disable protection request object
    container_uri = get_protection_container_uri_from_id(item.id)
    item_uri = get_protected_item_uri_from_id(item.id)

    # Trigger disable protection and wait for completion
    result = protected_item_client.delete(rs_vault.name, resource_group, "Azure", container_uri, item_uri, raw=True)
    wait_for_backup_operation(result, rs_vault.name, resource_group)

################# Private Methods
def get_protectable_item(vault_name, vault_rg, vm_name, vm_rg):
    protectable_item = try_get_protectable_item(vault_name, vault_rg, vm_name, vm_rg)
    if protectable_item is None:
        # Protectable item not found. Trigger discovery.
        refresh_result = protection_container_client.refresh(rs_vault.name, resource_group, "Azure", raw=True)
        wait_for_refresh(refresh_result, rs_vault.name, resource_group)
    protectable_item = try_get_protectable_item(vault_name, vault_rg, vm_name, vm_rg)    
    return protectable_item

def try_get_protectable_item(vault_name, vault_rg, vm_name, vm_rg):
    filter_string = get_filter_string({
        'backupManagementType' : 'AzureIaasVM'})
    
    protectable_items_paged = protectable_items_mgmt_client_factory(None).list(vault_name, vault_rg, filter_string)
    protectable_items = get_paged_list(protectable_items_paged)
    
    for protectable_item in protectable_items:
        item_vm_name = get_vm_name_from_vm_id(protectable_item.properties.virtual_machine_id)
        item_vm_rg = get_resource_group_from_id(protectable_item.properties.virtual_machine_id)
        if item_vm_name == vm_name and item_vm_rg == vm_rg:
            return protectable_item
    return None

def get_paged_list(obj_list):
    from msrest.paging import Paged

    if isinstance(obj_list, Paged):
        return list(obj_list)
    else:
        return obj_list

def get_one_or_many(obj_list):
    if len(obj_list) == 1:
        return obj_list[0]
    else:
        return obj_list

def get_item_type(workload_type):
    if workload_type == "AzureVM":
        return "VM"

def get_backup_management_type(container_type):
    if container_type == "AzureVM":
        return "AzureIaasVM"

def get_filter_string(filter_dict):
    filter_list = []
    for k, v in filter_dict.items():
        filter_list.append("{} eq '{}'".format(k, v))
    return " and ".join(filter_list)

def get_container_from_json(client, container):
    return get_object_from_json(client, container, 'ProtectionContainerResource')

def get_vault_from_json(client, vault):
    return get_object_from_json(client, vault, 'Vault')

def get_vm_from_json(client, vm):
    return get_object_from_json(client, vm, 'VirtualMachine')

def get_policy_from_json(client, policy):
    return get_object_from_json(client, policy, 'ProtectionPolicyResource')

def get_item_from_json(client, item):
    return get_object_from_json(client, item, 'ProtectedItemResource')

def get_object_from_json(client, object, class_name):
    param = None        
    with open(object) as f:
        json_obj = json.load(f)
        try:
            param = client._deserialize(class_name, json_obj)  # pylint: disable=protected-access
        except DeserializationError:
            pass
        if not param:
            raise ValueError("JSON file for object '{}' is not in correct format.".format(object))

    return param

def get_protection_container_uri_from_id(id):
    import re
    
    m = re.search('(?<=protectionContainers/)[^/]+'.format(str), id)
    return m.group(0)

def get_protectable_item_uri_from_id(id):
    import re
    
    m = re.search('(?<=protectableItems/)[^/]+'.format(str), id)
    return m.group(0)

def get_protected_item_uri_from_id(id):
    import re
    
    m = re.search('(?<=protectedItems/)[^/]+'.format(str), id)
    return m.group(0)

def get_vm_name_from_vm_id(id):
    import re
    
    m = re.search('(?<=virtualMachines/)[^/]+'.format(str), id)
    return m.group(0)

def get_resource_group_from_id(id):
    import re
    
    m = re.search('(?<=resourceGroups/)[^/]+'.format(str), id)
    return m.group(0)

def get_operation_id_from_header(header):
    from urllib.parse import urlparse

    parse_object = urlparse(header)
    return parse_object.path.split("/")[-1]

def wait_for_backup_operation(result, vault_name, resource_group):
    backup_operation_status_client = backup_operation_statuses_mgmt_client_factory(None)

    operation_id = get_operation_id_from_header(result.response.headers['Azure-AsyncOperation'])
    operation_status = backup_operation_status_client.get(vault_name, resource_group, operation_id)
    while operation_status.status == 'InProgress':
        time.sleep(1)
        operation_status = backup_operation_status_client.get(vault_name, resource_group, operation_id)

def dict_to_str(dict):
    str = ''
    for k, v in dict.items():
        str = str + "Key: {}, Value: {}\n".format(k, v)
    return str

def wait_for_refresh(result, vault_name, resource_group):
    refresh_operation_result_client = refresh_operation_results_mgmt_client_factory(None)

    operation_id = get_operation_id_from_header(result.response.headers['Location'])
    result = refresh_operation_result_client.get(vault_name, resource_group, 'Azure', operation_id, raw=True)
    while result.response.status_code == 202:
        time.sleep(1)
        result = refresh_operation_result_client.get(vault_name, resource_group, 'Azure', operation_id, raw=True)