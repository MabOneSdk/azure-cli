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

def vaults_mgmt_client_factory(_):
    return _common_client_factory().vaults

def containers_mgmt_client_factory(_):
    return _backup_client_factory().backup_protection_containers

def items_mgmt_client_factory(_):
    return _backup_client_factory().backup_protected_items