# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import azure.cli.command_modules.backup.custom_help as custom_help
# pylint: disable=import-error

from knack.log import get_logger

from azure.mgmt.recoveryservicesbackup.models import AzureVMAppContainerProtectionContainer, ProtectionContainerResource

from azure.cli.core.util import CLIError, sdk_no_wait
from azure.cli.command_modules.backup._client_factory import (
    backup_protected_items_cf, backup_protection_containers_cf, protectable_containers_cf)

logger = get_logger(__name__)

fabric_name = "Azure"
default_policy_name = "DefaultPolicy"
os_windows = 'Windows'
os_linux = 'Linux'
password_offset = 33
password_length = 15

# Mapping of workload type
workload_type_map = {'MSSQL': 'SQLDataBase',
                     'SAPHANA': 'SAPHanaDatabase'}


def show_wl_policy(client, resource_group_name, vault_name, name):
    return [client.get(vault_name, resource_group_name, name)]


def list_wl_policies(client, resource_group_name, vault_name, workload_type, backup_management_type):
    if workload_type is None:
        raise CLIError(
            """
            Workload type is required for Azure Workload.
            """)

    if backup_management_type is None:
        raise CLIError(
            """
            Backup Management Type needs to be specified for Azure Workload.
            """)

    workload_type = workload_type_map[workload_type]

    filter_string = custom_help._get_filter_string({
        'backupManagementType': backup_management_type,
        'workloadType': workload_type})

    policies = client.list(vault_name, resource_group_name, filter_string)
    return custom_help._get_list_from_paged_response(policies)


def list_protectable_containers(cmd, resource_group_name, vault_name, container_type="AzureWorkload"):
    filter_string = custom_help._get_filter_string({
        'backupManagementType': container_type
        })

    paged_containers = (protectable_containers_cf(cmd.cli_ctx)).list(vault_name, resource_group_name, fabric_name, filter_string)

    return custom_help. _get_list_from_paged_response(paged_containers)


def register_wl_container(cmd, client, vault_name, resource_group_name, workload_type, resource_id, container_type):
    workload_type = workload_type_map[workload_type]

    # Extracting friendly container name from resource id
    container_name = resource_id.split('/')[-1]

    containers = list_protectable_containers(cmd, resource_group_name, vault_name)

    for container in containers:
        if container.properties.friendly_name == container_name:
            container_name = container.name

    if container_name == resource_id.split('/')[-1]:
        raise CLIError(
            """
            Container unavailable or already registered.
            """)

    properties = AzureVMAppContainerProtectionContainer(backup_management_type=container_type, source_resource_id=resource_id, workload_type=workload_type)
    param = ProtectionContainerResource(properties=properties)

    result = sdk_no_wait(True, client.register,
                         vault_name, resource_group_name, fabric_name, container_name, param)
    return custom_help._track_register_operation(cmd.cli_ctx, result, vault_name, resource_group_name, container_name)


def re_register_wl_container(cmd, client, vault_name, resource_group_name, workload_type, container_name, container_type):
    workload_type = workload_type_map[workload_type]

    if not custom_help._is_native_name(container_name):
        raise CLIError(
            """
            Container name passed cannot be a friendly name.
            Please pass a native container name.
            """)

    containers = list_wl_containers(backup_protection_containers_cf(cmd.cli_ctx), resource_group_name, vault_name, container_type)
    source_resource_id = None

    for container in containers:
        if container.name == container_name:
            source_resource_id = container.properties.source_resource_id

    if not source_resource_id:
        raise CLIError(
            """
            No such registered container exists.
            """)

    properties = AzureVMAppContainerProtectionContainer(backup_management_type=container_type, workload_type=workload_type, operation_type='Reregister', source_resource_id=source_resource_id)
    param = ProtectionContainerResource(properties=properties)

    result = sdk_no_wait(True, client.register,
                         vault_name, resource_group_name, fabric_name, container_name, param)
    return custom_help._track_register_operation(cmd.cli_ctx, result, vault_name, resource_group_name, container_name)


def unregister_wl_container(cmd, client, vault_name, resource_group_name, container_name):
    if not custom_help._is_native_name(container_name):
        raise CLIError(
            """
            Container name passed cannot be a friendly name.
            Please pass a native container name.
            """)

    result = sdk_no_wait(True, client.unregister,
                         vault_name, resource_group_name, fabric_name, container_name)
    return custom_help._track_register_operation(cmd.cli_ctx, result, vault_name, resource_group_name, container_name)


def show_wl_container(client, name, resource_group_name, vault_name, container_type, status="Registered"):
    return custom_help._get_none_one_or_many(custom_help._get_containers(client, container_type, status, resource_group_name, vault_name, name))


def list_wl_containers(client, resource_group_name, vault_name, container_type, status="Registered"):
    return custom_help._get_containers(client, container_type, status, resource_group_name, vault_name)


def show_wl_item(client, resource_group_name, vault_name, container_name, name, workload_type):
    if workload_type is None:
        raise CLIError(
            """
            Workload type is required for Azure Workload.
            """)
    items = list_wl_items(client, resource_group_name, vault_name, workload_type, container_name)

    if custom_help._is_native_name(name):
        filtered_items = [item for item in items if item.name == name]
    else:
        filtered_items = [item for item in items if item.properties.friendly_name == name]

    return custom_help._get_none_one_or_many(filtered_items)


def list_wl_items(client, resource_group_name, vault_name, workload_type, container_name=None):
    item_type = workload_type_map[workload_type]

    filter_string = custom_help._get_filter_string({
        'backupManagementType': 'AzureWorkload',
        'itemType': item_type})

    items = client.list(vault_name, resource_group_name, filter_string)
    paged_items = custom_help._get_list_from_paged_response(items)
    if container_name:
        if custom_help._is_native_name(container_name):
            container_uri = container_name
        else:
            raise CLIError(
                """
                Container name passed cannot be a friendly name.
                Please pass a native container name.
                """)

        return [item for item in paged_items if
                custom_help._get_protection_container_uri_from_id(item.id).lower() == container_uri.lower()]
    return paged_items


def show_protectable_item(cmd, client, resource_group_name, vault_name, name, server_name, protectable_item_type,
                          workload_type, container_type="AzureWorkload"):
    items = list_protectable_items(cmd, client, resource_group_name, vault_name, workload_type, None, container_type)

    # Name filter
    if custom_help._is_native_name(name):
        filtered_items = [item for item in items if item.name == name]
    else:
        filtered_items = [item for item in items if item.properties.friendly_name == name]

    # Server Name filter
    filtered_items = [item for item in filtered_items if item.properties.server_name == server_name]

    # Protectable Item Type filter
    filtered_items = [item for item in filtered_items if item.properties.protectable_item_type == protectable_item_type]

    return custom_help._get_none_one_or_many(filtered_items)


def list_protectable_items(cmd, client, resource_group_name, vault_name, workload_type, container_name=None,
                           container_type="AzureWorkload"):
    workload_type = workload_type_map[workload_type]

    filter_string = custom_help._get_filter_string({
        'backupManagementType': container_type,
        'workloadType': workload_type,
        'containerName': container_name})

    # Items list
    items = client.list(vault_name, resource_group_name, filter_string)
    paged_items = custom_help._get_list_from_paged_response(items)

    if container_name:

        # Native name condition
        if custom_help._is_native_name(container_name):
            container_uri = container_name
        else:
            container = show_wl_container(backup_protection_containers_cf(cmd.cli_ctx),
                                          container_name, resource_group_name, vault_name)
            custom_help._validate_container(container)
            container_uri = container.name

        return [item for item in paged_items if
                custom_help._get_protection_container_uri_from_id(item.id).lower() == container_uri.lower()]
    return paged_items


def list_wl_recovery_points(cmd, client, resource_group_name, vault_name, container_name, item_name, workload_type,
                            start_date=None, end_date=None):
    item = show_wl_item(backup_protected_items_cf(cmd.cli_ctx), resource_group_name, vault_name,
                        container_name, item_name, workload_type)
    custom_help._validate_item(item)

    # Get container and item URIs
    container_uri = custom_help._get_protection_container_uri_from_id(item.id)
    item_uri = custom_help._get_protected_item_uri_from_id(item.id)

    query_end_date, query_start_date = custom_help._get_query_dates(end_date, start_date)

    if query_end_date and query_start_date:
        custom_help._is_range_valid(query_start_date, query_end_date)

    filter_string = custom_help._get_filter_string({
        'startDate': query_start_date,
        'endDate': query_end_date})

    if cmd.name.split()[2] == 'logchain':
        filter_string = custom_help._get_filter_string({
            'restorePointQueryType': 'Log',
            'startDate': query_start_date,
            'endDate': query_end_date})

    # Get recovery points
    recovery_points = client.list(vault_name, resource_group_name, fabric_name, container_uri, item_uri, filter_string)
    paged_recovery_points = custom_help._get_list_from_paged_response(recovery_points)

    return paged_recovery_points


def enable_protection_for_azure_wl():
    return


def backup_now():
    return


def disable_protection():
    return
