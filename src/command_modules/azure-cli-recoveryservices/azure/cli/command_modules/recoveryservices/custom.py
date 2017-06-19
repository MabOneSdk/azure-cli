# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import azure.cli.core.azlogging as azlogging
from azure.mgmt.recoveryservices.recovery_services_client import RecoveryServicesClient
from azure.mgmt.recoveryservices.models.vault import Vault
from azure.mgmt.recoveryservices.models.vault_properties import VaultProperties

logger = azlogging.get_az_logger(__name__)


def vaultcreds_download(example_param=None):
    result = {'example_param': example_param}
    return result

def show_default_vault(input_json):
    values = parse_json(input_json)
    vault = Vault() # Fill with default values
    return vault

def parse_json(json):
    values = None # parse from file
    return values
