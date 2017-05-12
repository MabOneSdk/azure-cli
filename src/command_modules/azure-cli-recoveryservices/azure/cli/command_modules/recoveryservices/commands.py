# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

#pylint: disable=line-too-long

from azure.cli.core.commands import cli_command
from azure.cli.command_modules.recoveryservices._client_factory import (
    vaults_mgmt_client_factory)
from azure.mgmt.recoveryservices.recovery_services_client import RecoveryServicesClient

cli_command(__name__, 'recoveryservices vaults list', 'azure.mgmt.recoveryservices.operations.vaults_operations#VaultsOperations.list_by_subscription_id', vaults_mgmt_client_factory)
cli_command(__name__, 'recoveryservices vaultcreds download', 'azure.cli.command_modules.recoveryservices.custom#vaultcreds_download')

