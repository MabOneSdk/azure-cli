# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

def _common_client_factory(**_):
    from azure.mgmt.recoveryservices import RecoveryServicesClient
    from azure.cli.core.commands.client_factory import get_mgmt_service_client
    
    return get_mgmt_service_client(RecoveryServicesClient)

def _backup_client_factory(**_):
    from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
    from azure.cli.core.commands.client_factory import get_mgmt_service_client
    
    return get_mgmt_service_client(RecoveryServicesBackupClient)

def _compute_client_factory(**_):
    from azure.cli.core.profiles import ResourceType
    from azure.cli.core.commands.client_factory import get_mgmt_service_client
    return get_mgmt_service_client(ResourceType.MGMT_COMPUTE)

def vaults_mgmt_client_factory(_):
    return _common_client_factory().vaults

def policies_mgmt_client_factory(_):
    return _backup_client_factory().backup_policies

def policy_mgmt_client_factory(_):
    return _backup_client_factory().protection_policies

def containers_mgmt_client_factory(_):
    return _backup_client_factory().backup_protection_containers

def items_mgmt_client_factory(_):
    return _backup_client_factory().backup_protected_items

def protectable_items_mgmt_client_factory(_):
    return _backup_client_factory().backup_protectable_items

def protected_items_mgmt_client_factory(_):
    return _backup_client_factory().protected_items

def vm_mgmt_client_factory(_):
    return _compute_client_factory().virtual_machines

def protection_containers_mgmt_client_factory(_):
    return _backup_client_factory().protection_containers

def backup_operation_statuses_mgmt_client_factory(_):
    return _backup_client_factory().backup_operation_statuses

def refresh_operation_results_mgmt_client_factory(_):
    return _backup_client_factory().protection_container_refresh_operation_results