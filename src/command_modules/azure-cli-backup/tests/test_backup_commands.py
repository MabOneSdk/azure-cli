# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import os
import unittest

from azure.cli.core.util import CLIError
from azure.cli.core.commands.arm import resource_id
from azure.cli.core.commands.client_factory import get_subscription_id
from azure.cli.core.test_utils.vcr_test_base import (VCRTestBase, ResourceGroupVCRTestBase, JMESPathCheck,
                                           NoneCheck, MOCKED_SUBSCRIPTION_ID)
from azure.cli.testsdk import ScenarioTest, ResourceGroupPreparer, StorageAccountPreparer
TEST_DIR = os.path.abspath(os.path.join(os.path.abspath(__file__), '..'))

class BackupTest(VCRTestBase):

    def __init__(self, test_method):
        super(BackupTest, self).__init__(__file__, test_method)

    def test_backup_items_list(self):
        self.execute()

#    def test_recoveryservices_vaults_list(self):
#        self.cmd('recoveryservices vaults list')

    def body(self):
        self.cmd("backup vault show -n pstestrsvault -g PsTestRg")
        self.cmd('backup item list --vault vault.json')
#        self.cmd('recoveryservices vaultcreds download')


if __name__ == '__main__':
    unittest.main()