# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import azure.cli.command_modules.backup.custom as custom
import azure.cli.command_modules.backup.custom_wl as custom_wl
# pylint: disable=import-error

from knack.log import get_logger

logger = get_logger(__name__)

fabric_name = "Azure"
default_policy_name = "DefaultPolicy"
os_windows = 'Windows'
os_linux = 'Linux'
password_offset = 33
password_length = 15


def show_container(client, name, resource_group_name, vault_name, container_type="AzureIaasVM", status="Registered"):
    if container_type == "AzureIaasVM":
        return custom.show_container(client, name, resource_group_name, vault_name, status)
    else:
        return custom_wl.show_wl_container(client, name, resource_group_name, vault_name, container_type)


def list_containers(client, resource_group_name, vault_name, container_type="AzureIaasVM", status="Registered"):
    if container_type == "AzureIaasVM":
        return custom.list_containers(client, resource_group_name, vault_name, status)
    else:
        return custom_wl.list_wl_containers(client, resource_group_name, vault_name, container_type)


def show_policy(client, resource_group_name, vault_name, name, container_type="AzureIaasVM"):
    if container_type == "AzureIaasVM":
        return custom.show_policy(client, resource_group_name, vault_name, name)
    else:
        return custom_wl.show_wl_policy(client, resource_group_name, vault_name, name)


def list_policies(client, resource_group_name, vault_name, workload_type=None, container_type="AzureIaasVM"):
    if container_type == "AzureIaasVM" and workload_type is None:
        return custom.list_policies(client, resource_group_name, vault_name)
    else:
        return custom_wl.list_wl_policies(client, resource_group_name, vault_name, workload_type, container_type)


def show_item(cmd, client, resource_group_name, vault_name, container_name, name, workload_type=None, container_type="AzureIaasVM"):
    if container_type == "AzureIaasVM" and workload_type is None:
        return custom.show_item(cmd, client, resource_group_name, vault_name, container_name, name)
    else:
        return custom_wl.show_wl_item(client, resource_group_name, vault_name, container_name, name, workload_type)


def list_items(cmd, client, resource_group_name, vault_name, workload_type=None, container_name=None, container_type="AzureIaasVM",
               item_type="VM"):
    if container_type == "AzureIaasVM":
        return custom.list_items(cmd, client, resource_group_name, vault_name, container_name)
    else:
        return custom_wl.list_wl_items(client, resource_group_name, vault_name, workload_type, container_name)


def list_recovery_points(cmd, client, resource_group_name, vault_name, container_name, item_name, workload_type=None,
                         container_type="AzureIaasVM", item_type="VM", start_date=None, end_date=None):
    if container_type == "AzureIaasVM" and workload_type is None:
        return custom.list_recovery_points(cmd, client, resource_group_name, vault_name, container_name, item_name,
                                           container_type, item_type, start_date, end_date)
    else:
        return custom_wl.list_wl_recovery_points(cmd, client, resource_group_name, vault_name, container_name, item_name, workload_type,
                                                 start_date, end_date)


def backup_now(cmd, client, resource_group_name, vault_name, container_name, item_name, retain_until,
               container_type="AzureIaasVM", item_type="VM"):
    if container_type == "AzureIaasVM":
        return custom.backup_now(cmd, client, resource_group_name, vault_name, container_name, item_name, retain_until,
                                 container_type, item_type)
    else:
        return custom_wl.backup_now()


def disable_protection(cmd, client, resource_group_name, vault_name, container_name, item_name,
                       container_type="AzureIaasVM", item_type="VM", delete_backup_data=False, **kwargs):
    if container_type == "AzureIaasVM":
        return custom.disable_protection(cmd, client, resource_group_name, vault_name, container_name, item_name,
                                         container_type, item_type, delete_backup_data, **kwargs)
    else:
        return custom_wl.disable_protection()


def list_protectable_items(cmd, client, resource_group_name, vault_name, workload_type, container_name=None,
                           container_type="AzureWorkload"):
    return custom_wl.list_protectable_items(cmd, client, resource_group_name, vault_name, workload_type, container_name,
                                            container_type)


def show_protectable_item(cmd, client, resource_group_name, vault_name, name, server_name, protectable_item_type,
                          workload_type, container_type="AzureWorkload"):
    return custom_wl.show_protectable_item(cmd, client, resource_group_name, vault_name, name, server_name, protectable_item_type,
                                           workload_type, container_type)


def show_recovery_point(cmd, client, resource_group_name, vault_name, container_name, item_name, name,
                        container_type="AzureIaasVM", item_type="VM"):
    return custom.show_recovery_point(cmd, client, resource_group_name, vault_name, container_name, item_name, name,
                                      container_type, item_type)


def unregister_wl_container(cmd, client, vault_name, resource_group_name, container_name):
    return custom_wl.unregister_wl_container(cmd, client, vault_name, resource_group_name, container_name)


def register_wl_container(cmd, client, vault_name, resource_group_name, workload_type, resource_id, container_type="AzureWorkload"):
    return custom_wl.register_wl_container(cmd, client, vault_name, resource_group_name, workload_type, resource_id, container_type)


def re_register_wl_container(cmd, client, vault_name, resource_group_name, workload_type, container_name, container_type="AzureWorkload"):
    return custom_wl.re_register_wl_container(cmd, client, vault_name, resource_group_name, workload_type, container_name, container_type)


def check_protection_enabled_for_vm(cmd, vm_id):
    return custom.check_protection_enabled_for_vm(cmd, vm_id)


def enable_protection_for_vm(cmd, client, resource_group_name, vault_name, vm, policy_name):
    return custom.enable_protection_for_vm(cmd, client, resource_group_name, vault_name, vm, policy_name)


def enable_protection_for_azure_wl():
    return custom_wl.enable_protection_for_azure_wl()
