# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import json

from msrest.exceptions import DeserializationError

from azure.mgmt.recoveryservices.models import Vault
from azure.mgmt.recoveryservicesbackup.models import ProtectedItemResource, AzureIaaSComputeVMProtectedItem

import azure.cli.core.azlogging as azlogging

from azure.cli.command_modules.backup._client_factory import (
    vm_mgmt_client_factory,
    policy_mgmt_client_factory,
    policies_mgmt_client_factory,
    containers_mgmt_client_factory,
    protectable_items_mgmt_client_factory,
    protected_items_mgmt_client_factory,
    items_mgmt_client_factory)

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
    policy_client = policy_mgmt_client_factory(None)

    vm = get_vm_from_json(vm_mgmt_client_factory(None), vm)
    rs_vault = get_vault_from_json(client, vault)
    resource_group = get_resource_group_from_id(rs_vault.id)
    policy = get_policy_from_json(policy_client, policy)

    vm_name = vm.name
    vm_rg = get_resource_group_from_id(vm.id)
    
    protectable_item = get_protectable_item(rs_vault.name, resource_group, vm_name, vm_rg)

    container_uri = get_container_uri_from_id(protectable_item.id)
    item_uri = get_item_uri_from_id(protectable_item.id)
    
    vm_item_properties = AzureIaaSComputeVMProtectedItem(policy_id=policy.id, source_resource_id=protectable_item.properties.virtual_machine_id)
    vm_item = ProtectedItemResource(properties=vm_item_properties)

    resp = protected_items_mgmt_client_factory(None).create_or_update(rs_vault.name, resource_group, "Azure", container_uri, item_uri, vm_item)

    return resp

################# Private Methods
def get_protectable_item(vault_name, vault_rg, vm_name, vm_rg):
    filter_string = get_filter_string({
        'backupManagementType' : 'AzureIaasVM'})
    
    protectable_items_paged = protectable_items_mgmt_client_factory(None).list(vault_name, vault_rg, filter_string)
    protectable_items = get_paged_list(protectable_items_paged)
    
    for protectable_item in protectable_items:
        item_vm_name = get_vm_name_from_vm_id(protectable_item.properties.virtual_machine_id)
        item_vm_rg = get_resource_group_from_id(protectable_item.properties.virtual_machine_id)
        if item_vm_name == vm_name and item_vm_rg == vm_rg:
            return protectable_item
    # we're still here, do discovery

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

def get_container_uri_from_id(id):
    import re
    
    m = re.search('(?<=protectionContainers/)[^/]+'.format(str), id)
    return m.group(0)

def get_item_uri_from_id(id):
    import re
    
    m = re.search('(?<=protectableItems/)[^/]+'.format(str), id)
    return m.group(0)

def get_vm_name_from_vm_id(id):
    import re
    
    m = re.search('(?<=virtualMachines/)[^/]+'.format(str), id)
    return m.group(0)

def get_resource_group_from_id(id):
    import re
    
    m = re.search('(?<=resourceGroups/)[^/]+'.format(str), id)
    return m.group(0)