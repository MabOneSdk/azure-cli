# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# pylint: disable=line-too-long

from argcomplete.completers import FilesCompleter
from azure.cli.core.commands import \
    (register_cli_argument, CliArgumentType)
from azure.cli.core.commands.parameters import \
    (resource_group_name_type, get_resource_name_completion_list, file_type)

# ARGUMENT DEFINITIONS

vault_name_type = CliArgumentType(help='Name of the vault.', options_list=('--vault-name',), completer=get_resource_name_completion_list('Microsoft.RecoveryServices/vaults'), id_part=None)

register_cli_argument('backup vault', 'resource_group_name', resource_group_name_type, help='Name of the resource group', completer=None, validator=None)
register_cli_argument('backup vault', 'vault_name', vault_name_type, options_list=('--name', '-n'))

register_cli_argument('backup container', 'vault', type=file_type, help='The file containing vault specification in JSON format.', completer=FilesCompleter())
register_cli_argument('backup container list', 'container_type', help='Container type.')
register_cli_argument('backup container list', 'status', help='Registration status.')

register_cli_argument('backup item', 'vault', type=file_type, help='The file containing vault specification in JSON format.', completer=FilesCompleter())