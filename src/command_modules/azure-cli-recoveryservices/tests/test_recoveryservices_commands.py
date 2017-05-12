import os
import unittest

from azure.cli.core.util import CLIError
from azure.cli.core.commands.arm import resource_id
from azure.cli.core.commands.client_factory import get_subscription_id
from azure.cli.core.test_utils.vcr_test_base import (VCRTestBase, ResourceGroupVCRTestBase, JMESPathCheck,
                                           NoneCheck, MOCKED_SUBSCRIPTION_ID)
from azure.cli.testsdk import ScenarioTest, ResourceGroupPreparer, StorageAccountPreparer
TEST_DIR = os.path.abspath(os.path.join(os.path.abspath(__file__), '..'))

class RecoveryServicesTest(VCRTestBase):

    def __init__(self, test_method):
        super(RecoveryServicesTest, self).__init__(__file__, test_method)

    def test_recoveryservices_vaultcreds_download(self):
        self.execute()

#    def test_recoveryservices_vaults_list(self):
#        self.cmd('recoveryservices vaults list')

    def body(self):
        self.cmd('recoveryservices vaults list')
#        self.cmd('recoveryservices vaultcreds download')


if __name__ == '__main__':
    unittest.main()