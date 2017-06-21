# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import json

from msrest.exceptions import DeserializationError

from azure.mgmt.recoveryservices.models import Vault

import azure.cli.core.azlogging as azlogging

from azure.cli.command_modules.backup._client_factory import (
    containers_mgmt_client_factory,
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

def get_resource_group_from_id(id):
    import re
    
    m = re.search('(?<=resourceGroups/)[^/]+', id)
    return m.group(0)