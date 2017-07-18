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
        vault_json = json.dumps(vault_json)
        
        policy_json = self.cmd('az backup policy list --vault \'{}\''.format(vault_json), checks=[
            JMESPathCheck('name', 'DefaultPolicy'),
            JMESPathCheck('resourceGroup', vault_rg)
        ]).get_output_in_json()
        policy_json = json.dumps(policy_json)

        vm_name = 'pstestv2vm2'
        vm_rg = vault_rg

        vm_json = self.cmd('az vm show -n {} -g {}'.format(vm_name, vm_rg)).get_output_in_json()
        vm_json = json.dumps(vm_json)

        self.cmd('az backup protection enable-for-vm --policy \'{}\' --vault \'{}\' --vm \'{}\''.format(policy_json, vault_json, vm_json))

        container_json = self.cmd('az backup container show --container-name \'{}\' --vault \'{}\''.format(vm_name, vault_json)).get_output_in_json()
        container_json = json.dumps(container_json)

        item_json = self.cmd('az backup item list --container \'{}\' --vault \'{}\''.format(container_json, vault_json)).get_output_in_json()
        item_json = json.dumps(item_json)

        self.cmd('az backup protection disable --backup-item \'{}\' --vault \'{}\''.format(item_json, vault_json))
