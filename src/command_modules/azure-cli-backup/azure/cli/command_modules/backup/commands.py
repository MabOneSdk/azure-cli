# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

#pylint: disable=line-too-long

from azure.cli.core.commands import cli_command
from azure.cli.command_modules.backup._client_factory import (
    vaults_mgmt_client_factory)

cli_command(__name__, 'backup vault show', 'azure.mgmt.recoveryservices.operations.vaults_operations#VaultsOperations.get', vaults_mgmt_client_factory)

cli_command(__name__, 'backup container list', 'azure.cli.command_modules.backup.custom#list_containers', vaults_mgmt_client_factory)
cli_command(__name__, 'backup item list', 'azure.cli.command_modules.backup.custom#items_list', vaults_mgmt_client_factory)


