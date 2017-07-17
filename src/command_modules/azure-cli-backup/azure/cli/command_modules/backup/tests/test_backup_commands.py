# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import json

from azure.cli.testsdk import ScenarioTest, JMESPathCheck

class BackupTests(ScenarioTest):
    def test_show_vault(self):
        vault_name = 'pstestrsvault'
        vault_rg = 'pstestrg'
        
        vault_json = self.cmd('az backup vault show -n {} -g {}'.format(vault_name, vault_rg), checks=[
            JMESPathCheck('name', vault_name),
            JMESPathCheck('resourceGroup', vault_rg)
        ]).get_output_in_json()
        
        policy_json = self.cmd('az backup policy list --vault \'{}\''.format(json.dumps(vault_json)), checks=[
            JMESPathCheck('name', 'DefaultPolicy'),
            JMESPathCheck('resourceGroup', vault_rg)
        ]).get_output_in_json()
