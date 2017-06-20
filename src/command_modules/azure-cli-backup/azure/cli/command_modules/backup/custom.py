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

def items_list(client, vault):
    rs_vault = get_vault_from_json(vault)    
    resource_group = get_resource_group_from_id(rs_vault.id)

    items = items_mgmt_client_factory(None).list(rs_vault.name, resource_group)
    return items

def list_containers(client, vault, container_type="AzureVM", status="Registered"):
    rs_vault = get_vault_from_json(client, vault)
    resource_group = get_resource_group_from_id(rs_vault.id)

    backup_management_type = get_backup_management_type(container_type)

    filter_string = get_filter_string({
        'backupManagementType' : backup_management_type, 
        'status' : status})

    containers = containers_mgmt_client_factory(None).list(rs_vault.name, resource_group, filter_string)
    return containers

def get_backup_management_type(container_type):
    if container_type is "AzureVM":
        return "AzureIaasVM"

def get_filter_string(filter_dict):
    filter_list = []
    for k, v in filter_dict.items():
        filter_list.append("{} eq '{}'".format(k, v))
    return " and ".join(filter_list)

def get_vault_from_json(client, vault):
    param = None        
    with open(vault) as f:
        json_obj = json.load(f)
        try:
            param = client._deserialize('Vault', json_obj)  # pylint: disable=protected-access
        except DeserializationError:
            pass
        if not param:
            raise ValueError("JSON file for vault '{}' is not in correct format.".format(vault))

    return param;

def get_resource_group_from_id(id):
    import re
    
    m = re.search('(?<=resourceGroups/)[^/]+', id)
    return m.group(0)