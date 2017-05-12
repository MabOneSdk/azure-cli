# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import azure.cli.core.azlogging as azlogging


logger = azlogging.get_az_logger(__name__)


def vaultcreds_download(example_param=None):
    result = {'example_param': example_param}
    return result