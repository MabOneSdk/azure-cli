# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import json
from datetime import datetime, timedelta
import unittest

from azure.cli.testsdk import ScenarioTest, JMESPathCheckExists, ResourceGroupPreparer, \
    StorageAccountPreparer
from azure.mgmt.recoveryservicesbackup.models import StorageType

from .preparers import VaultPreparer, VMPreparer, ItemPreparer, PolicyPreparer, RPPreparer


def _get_vm_version(vm_type):
    if vm_type == 'Microsoft.Compute/virtualMachines':
        return 'Compute'
    elif vm_type == 'Microsoft.ClassicCompute/virtualMachines':
        return 'Classic'


class BackupTests(ScenarioTest, unittest.TestCase):
    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer()
    @StorageAccountPreparer()
    def test_backup_scenario(self, resource_group, vault_name, vm_name, storage_account):

        self.kwargs.update({
            'vault': vault_name,
            'vm': vm_name
        })

        # Enable Protection
        self.cmd('backup protection enable-for-vm -g {rg} -v {vault} --vm {vm} -p DefaultPolicy').get_output_in_json()

        # Get Container
        self.kwargs['container'] = self.cmd('backup container show -n {vm} -v {vault} -g {rg} --query properties.friendlyName').get_output_in_json()

        # Get Item
        self.kwargs['item'] = self.cmd('backup item list -g {rg} -v {vault} -c {container} --query [0].properties.friendlyName').get_output_in_json()

        # Trigger Backup
        self.kwargs['retain_date'] = (datetime.utcnow() + timedelta(days=30)).strftime('%d-%m-%Y')
        self.kwargs['job'] = self.cmd('backup protection backup-now -g {rg} -v {vault} -c {container} -i {item} --retain-until {retain_date} --query name').get_output_in_json()
        self.cmd('backup job wait -g {rg} -v {vault} -n {job}')

        # Get Recovery Point
        self.kwargs['recovery_point'] = self.cmd('backup recoverypoint list -g {rg} -v {vault} -c {container} -i {item} --query [0].name').get_output_in_json()

        # Trigger Restore
        self.kwargs['job'] = self.cmd('backup restore restore-disks -g {rg} -v {vault} -c {container} -i {item} -r {recovery_point} --storage-account {sa} --query name --restore-to-staging-storage-account').get_output_in_json()
        self.cmd('backup job wait -g {rg} -v {vault} -n {job}')

        # Disable Protection
        self.cmd('backup protection disable -g {rg} -v {vault} -c {container} -i {item} --delete-backup-data true --yes')

    @ResourceGroupPreparer()
    @VaultPreparer(parameter_name='vault1')
    @VaultPreparer(parameter_name='vault2')
    def test_backup_vault(self, resource_group, resource_group_location, vault1, vault2):

        self.kwargs.update({
            'loc': resource_group_location,
            'vault1': vault1,
            'vault2': vault2
        })

        self.kwargs['vault3'] = self.create_random_name('clitest-vault', 50)
        self.cmd('backup vault create -n {vault3} -g {rg} -l {loc}', checks=[
            self.check('name', '{vault3}'),
            self.check('resourceGroup', '{rg}'),
            self.check('location', '{loc}'),
            self.check('properties.provisioningState', 'Succeeded')
        ])

        self.kwargs['vault4'] = self.create_random_name('clitest-vault', 50)
        self.cmd('backup vault create -n {vault4} -g {rg} -l {loc}', checks=[
            self.check('name', '{vault4}'),
            self.check('resourceGroup', '{rg}'),
            self.check('location', '{loc}'),
            self.check('properties.provisioningState', 'Succeeded')
        ])

        number_of_test_vaults = 4

        self.cmd('backup vault list', checks=[
            self.check("length([?resourceGroup == '{rg}'])", number_of_test_vaults),
            self.check("length([?name == '{vault1}'])", 1),
            self.check("length([?name == '{vault2}'])", 1),
            self.check("length([?name == '{vault3}'])", 1),
            self.check("length([?name == '{vault4}'])", 1)
        ])

        self.cmd('backup vault list -g {rg}', checks=[
            self.check("length(@)", number_of_test_vaults),
            self.check("length([?name == '{vault1}'])", 1),
            self.check("length([?name == '{vault2}'])", 1),
            self.check("length([?name == '{vault3}'])", 1),
            self.check("length([?name == '{vault4}'])", 1)
        ])

        storage_model_types = [e.value for e in StorageType]
        vault_properties = self.cmd('backup vault backup-properties show -n {vault1} -g {rg}', checks=[
            JMESPathCheckExists("contains({}, properties.storageModelType)".format(storage_model_types)),
            self.check('properties.storageTypeState', 'Unlocked'),
            self.check('resourceGroup', '{rg}')
        ]).get_output_in_json()

        if vault_properties['properties']['storageModelType'] == StorageType.geo_redundant.value:
            new_storage_model = StorageType.locally_redundant.value
        else:
            new_storage_model = StorageType.geo_redundant.value

        self.kwargs['model'] = new_storage_model
        self.cmd('backup vault backup-properties set -n {vault1} -g {rg} --backup-storage-redundancy {model}')

        self.cmd('backup vault backup-properties show -n {vault1} -g {rg}', checks=[
            self.check('properties.storageModelType', new_storage_model)
        ])

        self.cmd('backup vault delete -n {vault4} -g {rg} -y')

        self.cmd('backup vault list', checks=[
            self.check("length([?resourceGroup == '{rg}'])", number_of_test_vaults - 1),
            self.check("length([?name == '{vault1}'])", 1),
            self.check("length([?name == '{vault2}'])", 1),
            self.check("length([?name == '{vault3}'])", 1)
        ])

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer(parameter_name='vm1')
    @VMPreparer(parameter_name='vm2')
    @ItemPreparer(vm_parameter_name='vm1')
    @ItemPreparer(vm_parameter_name='vm2')
    def test_backup_container(self, resource_group, vault_name, vm1, vm2):

        self.kwargs.update({
            'vault': vault_name,
            'vm1': vm1,
            'vm2': vm2
        })

        container_json = self.cmd('backup container show -n {vm1} -v {vault} -g {rg}', checks=[
            self.check('properties.friendlyName', '{vm1}'),
            self.check('properties.healthStatus', 'Healthy'),
            self.check('properties.registrationStatus', 'Registered'),
            self.check('properties.resourceGroup', '{rg}'),
            self.check('resourceGroup', '{rg}')
        ]).get_output_in_json()

        self.kwargs['container_name'] = container_json['name']

        self.cmd('backup container show -n {container_name} -v {vault} -g {rg}', checks=[
            self.check('properties.friendlyName', '{vm1}'),
            self.check('properties.healthStatus', 'Healthy'),
            self.check('properties.registrationStatus', 'Registered'),
            self.check('properties.resourceGroup', '{rg}'),
            self.check('name', '{container_name}'),
            self.check('resourceGroup', '{rg}')
        ]).get_output_in_json()

        vm1_json = self.cmd('vm show -n {vm1} -g {rg}').get_output_in_json()

        self.assertIn(vault_name.lower(), container_json['id'].lower())
        self.assertIn(vm1.lower(), container_json['name'].lower())
        self.assertIn(vm1.lower(), container_json['properties']['virtualMachineId'].lower())
        self.assertEqual(container_json['properties']['virtualMachineVersion'], _get_vm_version(vm1_json['type']))

        self.cmd('backup container list -v {vault} -g {rg}', checks=[
            self.check("length(@)", 2),
            self.check("length([?properties.friendlyName == '{vm1}'])", 1),
            self.check("length([?properties.friendlyName == '{vm2}'])", 1)])

    def test_backup_wl_container(self, container_name1='shrac3', container_name2='shrac2', resource_group='shracrg', vault_name='shracsql'):

        self.kwargs.update({
            'vault': vault_name,
            'name1': container_name1,
            'name2': container_name2,
            'rg': resource_group,
            'rvault': 'pstestwlRSV1bca8',
            'rrg': 'pstestwlRG1bca8',
            'rname': 'VMAppContainer;Compute;pstestwlRG1bca8;pstestwlvm1bca8',
            'rid': '/subscriptions/da364f0f-307b-41c9-9d47-b7413ec45535/resourceGroups/pstestwlRG1bca8/providers/Microsoft.Compute/virtualMachines/pstestwlvm1bca8'
        })

        self.cmd('backup container list -v {rvault} -g {rrg} -bmt AzureWorkload', checks=[
            self.check("length([?name == '{rname}'])", 0)])

        self.cmd('backup container register -v {rvault} -g {rrg} -bmt AzureWorkload -wt MSSQL -id {rid}')

        self.cmd('backup container list -v {rvault} -g {rrg} -bmt AzureWorkload', checks=[
            self.check("length([?name == '{rname}'])", 1)])

        self.cmd('backup container re-register -v {rvault} -g {rrg} -bmt AzureWorkload -wt MSSQL -y -n{rname}')

        self.cmd('backup container list -v {rvault} -g {rrg} -bmt AzureWorkload', checks=[
            self.check("length([?name == '{rname}'])", 1)])

        self.cmd('backup container unregister -v {rvault} -g {rrg} -n {rname} -y')

        self.cmd('backup container list -v {rvault} -g {rrg} -bmt AzureWorkload', checks=[
            self.check("length([?name == '{rname}'])", 0)])

        self.cmd('account set -s f879818f-5b29-4a43-8961-34169783144f')

        container_json = self.cmd('backup container show -n {name1} -v {vault} -g {rg} -bmt AzureWorkload', checks=[
            self.check('properties.friendlyName', '{name1}'),
            self.check('properties.healthStatus', 'Healthy'),
            self.check('properties.registrationStatus', 'Registered'),
            self.check('resourceGroup', '{rg}')
        ]).get_output_in_json()

        self.kwargs['container_name'] = container_json['name']

        self.cmd('backup container show -n {container_name} -v {vault} -g {rg} -bmt AzureWorkload', checks=[
            self.check('properties.friendlyName', '{name1}'),
            self.check('properties.healthStatus', 'Healthy'),
            self.check('properties.registrationStatus', 'Registered'),
            self.check('name', '{container_name}'),
            self.check('resourceGroup', '{rg}')
        ]).get_output_in_json()

        self.assertIn(vault_name.lower(), container_json['id'].lower())
        self.assertIn(container_name1.lower(), container_json['name'].lower())

        self.cmd('backup container list -v {vault} -g {rg} -bmt AzureWorkload', checks=[
            # self.check("length(@)", 2),
            self.check("length([?properties.friendlyName == '{name1}'])", 1),
            self.check("length([?properties.friendlyName == '{name2}'])", 1)])

    @ResourceGroupPreparer()
    @VaultPreparer()
    @PolicyPreparer(parameter_name='policy1')
    @PolicyPreparer(parameter_name='policy2')
    @VMPreparer(parameter_name='vm1')
    @VMPreparer(parameter_name='vm2')
    @ItemPreparer(vm_parameter_name='vm1')
    @ItemPreparer(vm_parameter_name='vm2')
    def test_backup_policy(self, resource_group, vault_name, policy1, policy2, vm1, vm2):

        self.kwargs.update({
            'policy1': policy1,
            'policy2': policy2,
            'policy3': self.create_random_name('clitest-policy', 24),
            'default': 'DefaultPolicy',
            'vault': vault_name,
            'vm1': vm1,
            'vm2': vm2
        })

        self.kwargs['policy1_json'] = self.cmd('backup policy show -g {rg} -v {vault} -n {policy1}', checks=[
            self.check('name', '{policy1}'),
            self.check('resourceGroup', '{rg}')
        ]).get_output_in_json()

        self.cmd('backup policy list -g {rg} -v {vault}', checks=[
            self.check("length(@)", 4),
            self.check("length([?name == '{default}'])", 1),
            self.check("length([?name == '{policy1}'])", 1),
            self.check("length([?name == '{policy2}'])", 1)
        ])

        self.kwargs['instantRpRetentionRangeInDays'] = 2
        self.kwargs['policy1_json']['name'] = self.kwargs['policy3']
        self.kwargs['policy1_json']['properties']['instantRpRetentionRangeInDays'] = 2
        self.kwargs['policy1_json'] = json.dumps(self.kwargs['policy1_json'])

        self.cmd("backup policy set -g {rg} -v {vault} --policy '{policy1_json}'", checks=[
            self.check('name', '{policy3}'),
            self.check('resourceGroup', '{rg}')
        ])

        self.kwargs['policy1_json'] = self.cmd('backup policy show -g {rg} -v {vault} -n {policy1}', checks=[
            self.check('name', '{policy1}'),
            self.check('resourceGroup', '{rg}'),
            self.check('properties.instantRpRetentionRangeInDays', '{instantRpRetentionRangeInDays}')
        ]).get_output_in_json()

        self.cmd('backup policy list-associated-items -g {rg} -v {vault} -n {default}', checks=[
            self.check("length(@)", 2),
            self.check("length([?properties.friendlyName == '{}'])".format(vm1), 1),
            self.check("length([?properties.friendlyName == '{}'])".format(vm2), 1)
        ])

        self.cmd('backup policy list -g {rg} -v {vault}', checks=[
            self.check("length(@)", 5),
            self.check("length([?name == '{default}'])", 1),
            self.check("length([?name == '{policy1}'])", 1),
            self.check("length([?name == '{policy2}'])", 1),
            self.check("length([?name == '{policy3}'])", 1)
        ])

        self.cmd('backup policy delete -g {rg} -v {vault} -n {policy3}')

        self.cmd('backup policy list -g {rg} -v {vault}', checks=[
            self.check("length(@)", 4),
            self.check("length([?name == '{default}'])", 1),
            self.check("length([?name == '{policy1}'])", 1),
            self.check("length([?name == '{policy2}'])", 1)
        ])

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer(parameter_name='vm1')
    @VMPreparer(parameter_name='vm2')
    @ItemPreparer(vm_parameter_name='vm1')
    @ItemPreparer(vm_parameter_name='vm2')
    @PolicyPreparer()
    def test_backup_item(self, resource_group, vault_name, vm1, vm2, policy_name):

        self.kwargs.update({
            'vault': vault_name,
            'vm1': vm1,
            'vm2': vm2,
            'policy': policy_name,
            'default': 'DefaultPolicy'
        })
        self.kwargs['container1'] = self.cmd('backup container show -n {vm1} -v {vault} -g {rg} --query properties.friendlyName').get_output_in_json()
        self.kwargs['container2'] = self.cmd('backup container show -n {vm2} -v {vault} -g {rg} --query properties.friendlyName').get_output_in_json()

        item1_json = self.cmd('backup item show -g {rg} -v {vault} -c {container1} -n {vm1}', checks=[
            self.check('properties.friendlyName', '{vm1}'),
            self.check('properties.healthStatus', 'Passed'),
            self.check('properties.protectionState', 'IRPending'),
            self.check('properties.protectionStatus', 'Healthy'),
            self.check('resourceGroup', '{rg}')
        ]).get_output_in_json()

        self.assertIn(vault_name.lower(), item1_json['id'].lower())
        self.assertIn(vm1.lower(), item1_json['name'].lower())
        self.assertIn(vm1.lower(), item1_json['properties']['sourceResourceId'].lower())
        self.assertIn(vm1.lower(), item1_json['properties']['virtualMachineId'].lower())
        self.assertIn(self.kwargs['default'].lower(), item1_json['properties']['policyId'].lower())

        self.kwargs['container1_fullname'] = self.cmd('backup container show -n {vm1} -v {vault} -g {rg} --query name').get_output_in_json()

        self.cmd('backup item show -g {rg} -v {vault} -c {container1_fullname} -n {vm1}', checks=[
            self.check('properties.friendlyName', '{vm1}'),
            self.check('properties.healthStatus', 'Passed'),
            self.check('properties.protectionState', 'IRPending'),
            self.check('properties.protectionStatus', 'Healthy'),
            self.check('resourceGroup', '{rg}')
        ])

        self.kwargs['item1_fullname'] = item1_json['name']

        self.cmd('backup item show -g {rg} -v {vault} -c {container1_fullname} -n {item1_fullname}', checks=[
            self.check('properties.friendlyName', '{vm1}'),
            self.check('properties.healthStatus', 'Passed'),
            self.check('properties.protectionState', 'IRPending'),
            self.check('properties.protectionStatus', 'Healthy'),
            self.check('resourceGroup', '{rg}')
        ])

        self.cmd('backup item list -g {rg} -v {vault} -c {container1}', checks=[
            self.check("length(@)", 1),
            self.check("length([?properties.friendlyName == '{vm1}'])", 1)
        ])

        self.cmd('backup item list -g {rg} -v {vault} -c {container1_fullname}', checks=[
            self.check("length(@)", 1),
            self.check("length([?properties.friendlyName == '{vm1}'])", 1)
        ])

        self.cmd('backup item list -g {rg} -v {vault} -c {container2}', checks=[
            self.check("length(@)", 1),
            self.check("length([?properties.friendlyName == '{vm2}'])", 1)
        ])

        self.cmd('backup item list -g {rg} -v {vault}', checks=[
            self.check("length(@)", 2),
            self.check("length([?properties.friendlyName == '{vm1}'])", 1),
            self.check("length([?properties.friendlyName == '{vm2}'])", 1)
        ])

        self.cmd('backup item set-policy -g {rg} -v {vault} -c {container1} -n {vm1} -p {policy}', checks=[
            self.check("properties.entityFriendlyName", '{vm1}'),
            self.check("properties.operation", "ConfigureBackup"),
            self.check("properties.status", "Completed"),
            self.check("resourceGroup", '{rg}')
        ])

        item1_json = self.cmd('backup item show -g {rg} -v {vault} -c {container1} -n {vm1}').get_output_in_json()
        self.assertIn(policy_name.lower(), item1_json['properties']['policyId'].lower())

    def test_backup_wl_item(self, container_name1='shrac3', container_name2='shrac2', resource_group='shracrg', vault_name='shracsql', policy_name='HourlyLogBackup'):

        self.kwargs.update({
            'vault': vault_name,
            'name1': container_name1,
            'name2': container_name2,
            'policy': policy_name,
            'default': 'HourlyLogBackup',
            'rg': resource_group,
            'item1': "shracsqldb101",
            'item2': "dogfooddb103"
        })

        self.kwargs['container1'] = self.cmd('backup container show -n {name1} -v {vault} -g {rg} -bmt AzureWorkload --query name').get_output_in_json()
        self.kwargs['container2'] = self.cmd('backup container show -n {name2} -v {vault} -g {rg} -bmt AzureWorkload --query name').get_output_in_json()

        item1_json = self.cmd('backup item show -g {rg} -v {vault} -c {container1} -n {item1} -bmt AzureWorkload -wt MSSQL', checks=[
            self.check('properties.friendlyName', '{item1}'),
            self.check('properties.protectedItemHealthStatus', 'NotReachable'),
            self.check('properties.protectionState', 'IRPending'),
            self.check('properties.protectionStatus', 'Healthy'),
            self.check('resourceGroup', '{rg}')
        ]).get_output_in_json()

        self.assertIn(vault_name.lower(), item1_json['id'].lower())
        self.assertIn(container_name1.lower(), item1_json['properties']['containerName'].lower())
        self.assertIn(container_name1.lower(), item1_json['properties']['sourceResourceId'].lower())
        self.assertIn(self.kwargs['default'].lower(), item1_json['properties']['policyId'].lower())

        self.kwargs['container1_fullname'] = self.cmd('backup container show -n {name1} -v {vault} -g {rg} -bmt AzureWorkload --query name').get_output_in_json()

        self.cmd('backup item show -g {rg} -v {vault} -c {container1_fullname} -n {item1} -bmt AzureWorkload -wt MSSQL', checks=[
            self.check('properties.friendlyName', '{item1}'),
            self.check('properties.protectedItemHealthStatus', 'NotReachable'),
            self.check('properties.protectionState', 'IRPending'),
            self.check('properties.protectionStatus', 'Healthy'),
            self.check('resourceGroup', '{rg}')
        ])

        self.kwargs['item1_fullname'] = item1_json['name']

        self.cmd('backup item show -g {rg} -v {vault} -c {container1_fullname} -n {item1_fullname} -bmt AzureWorkload -wt MSSQL', checks=[
            self.check('properties.friendlyName', '{item1}'),
            self.check('properties.protectedItemHealthStatus', 'NotReachable'),
            self.check('properties.protectionState', 'IRPending'),
            self.check('properties.protectionStatus', 'Healthy'),
            self.check('resourceGroup', '{rg}')
        ])

        self.cmd('backup item list -g {rg} -v {vault} -c {container1} -bmt AzureWorkload -wt MSSQL', checks=[
            # self.check("length(@)", 1),
            self.check("length([?properties.friendlyName == '{item1}'])", 1)
        ])

        self.cmd('backup item list -g {rg} -v {vault} -c {container1_fullname} -bmt AzureWorkload -wt MSSQL', checks=[
            # self.check("length(@)", 1),
            self.check("length([?properties.friendlyName == '{item1}'])", 1)
        ])

        self.cmd('backup item list -g {rg} -v {vault} -c {container2} -bmt AzureWorkload -wt MSSQL', checks=[
            self.check("length(@)", 1),
            self.check("length([?properties.friendlyName == '{item2}'])", 1)
        ])

        self.cmd('backup item list -g {rg} -v {vault} -bmt AzureWorkload -wt MSSQL', checks=[
            # self.check("length(@)", 2),
            self.check("length([?properties.friendlyName == '{item1}'])", 1),
            self.check("length([?properties.friendlyName == '{item2}'])", 1)
        ])

        # self.cmd('backup item set-policy -g {rg} -v {vault} -c {container1} -n {item1} -p {policy}', checks=[
        #    self.check("properties.entityFriendlyName", '{item1}'),
        #    self.check("properties.operation", "ConfigureBackup"),
        #    self.check("properties.status", "Completed"),
        #    self.check("resourceGroup", '{rg}')
        # ])

        item1_json = self.cmd('backup item show -g {rg} -v {vault} -c {container1} -n {item1} -wt MSSQL').get_output_in_json()
        self.assertIn(policy_name.lower(), item1_json['properties']['policyId'].lower())

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer()
    @ItemPreparer()
    @RPPreparer()
    @RPPreparer()
    def test_backup_rp(self, resource_group, vault_name, vm_name):

        self.kwargs.update({
            'vault': vault_name,
            'vm': vm_name
        })
        rp_names = self.cmd('backup recoverypoint list -g {rg} -v {vault} -c {vm} -i {vm} --query [].name', checks=[
            self.check("length(@)", 2)
        ]).get_output_in_json()

        self.kwargs['rp1'] = rp_names[0]
        rp1_json = self.cmd('backup recoverypoint show -g {rg} -v {vault} -c {vm} -i {vm} -n {rp1}', checks=[
            self.check("name", '{rp1}'),
            self.check("resourceGroup", '{rg}')
        ]).get_output_in_json()
        self.assertIn(vault_name.lower(), rp1_json['id'].lower())
        self.assertIn(vm_name.lower(), rp1_json['id'].lower())

        self.kwargs['rp2'] = rp_names[1]
        rp2_json = self.cmd('backup recoverypoint show -g {rg} -v {vault} -c {vm} -i {vm} -n {rp2}', checks=[
            self.check("name", '{rp2}'),
            self.check("resourceGroup", '{rg}')
        ]).get_output_in_json()
        self.assertIn(vault_name.lower(), rp2_json['id'].lower())
        self.assertIn(vm_name.lower(), rp2_json['id'].lower())

    def test_backup_wl_rp(self, container_name='VMAppContainer;compute;shracrg;shrac4', resource_group='shracrg', vault_name='shracsql', item_name='msdb'):

        self.kwargs.update({
            'vault': vault_name,
            'name': container_name,
            'rg': resource_group,
            'item': item_name
        })
        self.cmd('backup recoverypoint list -g {rg} -v {vault} -c {name} -i {item} -wt MSSQL --query [].name', checks=[
            self.check("length(@)", 2)
        ]).get_output_in_json()

        rp1_json = self.cmd('backup recoverypoint logchain show -g {rg} -v {vault} -c {name} -i {item} -wt MSSQL', checks=[
            self.check('[].resourceGroup', '[\'{rg}\']')
        ]).get_output_in_json()
        self.assertIn(vault_name.lower(), rp1_json[0]['id'].lower())
        self.assertIn(container_name.lower(), rp1_json[0]['id'].lower())

        rp2_json = self.cmd('backup recoverypoint logchain show -g {rg} -v {vault} -c {name} -i {item} -wt MSSQL', checks=[
            self.check('[].resourceGroup', '[\'{rg}\']')
        ]).get_output_in_json()
        self.assertIn(vault_name.lower(), rp2_json[0]['id'].lower())
        self.assertIn(container_name.lower(), rp2_json[0]['id'].lower())

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer()
    def test_backup_protection(self, resource_group, vault_name, vm_name):

        self.kwargs.update({
            'vault': vault_name,
            'vm': vm_name
        })

        self.kwargs['vm_id'] = self.cmd('vm show -g {rg} -n {vm} --query id').get_output_in_json()

        protection_check = self.cmd('backup protection check-vm --vm-id {vm_id}').output
        self.assertTrue(protection_check == '')

        self.cmd('backup protection enable-for-vm -g {rg} -v {vault} --vm {vm} -p DefaultPolicy', checks=[
            self.check("properties.entityFriendlyName", '{vm}'),
            self.check("properties.operation", "ConfigureBackup"),
            self.check("properties.status", "Completed"),
            self.check("resourceGroup", '{rg}')
        ])

        vault_id = self.cmd('backup vault show -g {rg} -n {vault} --query id').get_output_in_json()

        vault_id_check = self.cmd('backup protection check-vm --vm-id {vm_id}').get_output_in_json()
        self.assertIsNotNone(vault_id_check)
        self.assertTrue(vault_id.lower() == vault_id_check.lower())

        self.cmd('backup protection disable -g {rg} -v {vault} -c {vm} -i {vm} --yes', checks=[
            self.check("properties.entityFriendlyName", '{vm}'),
            self.check("properties.operation", "DisableBackup"),
            self.check("properties.status", "Completed"),
            self.check("resourceGroup", '{rg}')
        ])

        self.cmd('backup item show -g {rg} -v {vault} -c {vm} -n {vm}', checks=[
            self.check("properties.friendlyName", '{vm}'),
            self.check("properties.protectionState", "ProtectionStopped"),
            self.check("resourceGroup", '{rg}')
        ])

        self.cmd('backup protection disable -g {rg} -v {vault} -c {vm} -i {vm} --delete-backup-data true --yes', checks=[
            self.check("properties.entityFriendlyName", '{vm}'),
            self.check("properties.operation", "DeleteBackupData"),
            self.check("properties.status", "Completed"),
            self.check("resourceGroup", '{rg}')
        ])

        self.cmd('backup container list -v {vault} -g {rg}',
                 checks=self.check("length(@)", 0))

        protection_check = self.cmd('backup protection check-vm --vm-id {vm_id}').output
        self.assertTrue(protection_check == '')

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer()
    @ItemPreparer()
    @RPPreparer()
    @StorageAccountPreparer()
    def test_backup_restore(self, resource_group, vault_name, vm_name, storage_account):

        self.kwargs.update({
            'vault': vault_name,
            'vm': vm_name
        })
        self.kwargs['rp'] = self.cmd('backup recoverypoint list -g {rg} -v {vault} -c {vm} -i {vm} --query [0].name').get_output_in_json()

        # Original Storage Account Restore Fails
        self.cmd('backup restore restore-disks -g {rg} -v {vault} -c {vm} -i {vm} -r {rp} --storage-account {sa} --restore-to-staging-storage-account false', expect_failure=True)

        # Trigger Restore
        trigger_restore_job_json = self.cmd('backup restore restore-disks -g {rg} -v {vault} -c {vm} -i {vm} -r {rp} --storage-account {sa} --restore-to-staging-storage-account', checks=[
            self.check("properties.entityFriendlyName", '{vm}'),
            self.check("properties.operation", "Restore"),
            self.check("properties.status", "InProgress"),
            self.check("resourceGroup", '{rg}')
        ]).get_output_in_json()
        self.kwargs['job'] = trigger_restore_job_json['name']
        self.cmd('backup job wait -g {rg} -v {vault} -n {job}')

        trigger_restore_job_details = self.cmd('backup job show -g {rg} -v {vault} -n {job}', checks=[
            self.check("properties.entityFriendlyName", '{vm}'),
            self.check("properties.operation", "Restore"),
            self.check("properties.status", "Completed"),
            self.check("resourceGroup", '{rg}')
        ]).get_output_in_json()

        property_bag = trigger_restore_job_details['properties']['extendedInfo']['propertyBag']
        self.assertEqual(property_bag['Target Storage Account Name'], storage_account)

        self.kwargs['container'] = property_bag['Config Blob Container Name']
        self.kwargs['blob'] = property_bag['Config Blob Name']

        self.cmd('storage blob exists --account-name {sa} -c {container} -n {blob}',
                 checks=self.check("exists", True))

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer()
    @ItemPreparer()
    @RPPreparer()
    @StorageAccountPreparer()
    def test_backup_job(self, resource_group, vault_name, vm_name, storage_account):

        self.kwargs.update({
            'vault': vault_name,
            'vm': vm_name
        })
        self.kwargs['rp'] = self.cmd('backup recoverypoint list -g {rg} -v {vault} -c {vm} -i {vm} --query [0].name').get_output_in_json()
        self.kwargs['job'] = self.cmd('backup restore restore-disks -g {rg} -v {vault} -c {vm} -i {vm} -r {rp} --storage-account {sa} --query name --restore-to-staging-storage-account').get_output_in_json()

        self.cmd('backup job show -g {rg} -v {vault} -n {job}', checks=[
            self.check("name", '{job}'),
            self.check("properties.entityFriendlyName", '{vm}'),
            self.check("properties.operation", "Restore"),
            self.check("properties.status", "InProgress"),
            self.check("resourceGroup", '{rg}')
        ])

        self.cmd('backup job list -g {rg} -v {vault}',
                 checks=self.check("length([?name == '{job}'])", 1))

        self.cmd('backup job list -g {rg} -v {vault} --status InProgress',
                 checks=self.check("length([?name == '{job}'])", 1))

        self.cmd('backup job list -g {rg} -v {vault} --operation Restore',
                 checks=self.check("length([?name == '{job}'])", 1))

        self.cmd('backup job list -g {rg} -v {vault} --operation Restore --status InProgress',
                 checks=self.check("length([?name == '{job}'])", 1))

        self.cmd('backup job stop -g {rg} -v {vault} -n {job}')

    def test_backup_protectable_item(self, container_name1='shrac3', container_name2='shrac2', resource_group='shracrg', vault_name='shracsql', policy_name='HourlyLogBackup'):

        self.kwargs.update({
            'vault': vault_name,
            'name1': container_name1,
            'name2': container_name2,
            'policy': policy_name,
            'default': 'HourlyLogBackup',
            'rg': resource_group,
            'item1': "shracsqldb101",
            'item2': "dogfooddb103",
            'name': 'mssqlserer'
        })

        # self.kwargs['container1'] = self.cmd('backup container show -n {name1} -v {vault} -g {rg} --query properties.friendlyName').get_output_in_json()
        # self.kwargs['container2'] = self.cmd('backup container show -n {name2} -v {vault} -g {rg} --query properties.friendlyName').get_output_in_json()

        self.kwargs['name'] = self.cmd('backup protectable-item list -g {rg} -v {vault} --query [0].name').get_output_in_json()

        item1_json = self.cmd('backup protectable-item show -g {rg} -v {vault} -n {name}', checks=[
            self.check('properties.friendlyName', '{name}'),
            self.check('properties.protectedItemHealthStatus', 'NotReachable'),
            self.check('properties.protectionState', 'IRPending'),
            self.check('properties.protectionStatus', 'Healthy'),
            self.check('resourceGroup', '{rg}')
        ]).get_output_in_json()

        self.assertIn(vault_name.lower(), item1_json['id'].lower())
        self.assertIn(container_name1.lower(), item1_json['properties']['containerName'].lower())
        self.assertIn(container_name1.lower(), item1_json['properties']['sourceResourceId'].lower())
        self.assertIn(self.kwargs['default'].lower(), item1_json['properties']['policyId'].lower())

        self.kwargs['container1_fullname'] = self.cmd('backup container show -n {name1} -v {vault} -g {rg} --query name').get_output_in_json()

        self.cmd('backup item show -g {rg} -v {vault} -c {container1_fullname} -n {item1}', checks=[
            self.check('properties.friendlyName', '{item1}'),
            self.check('properties.protectedItemHealthStatus', 'NotReachable'),
            self.check('properties.protectionState', 'IRPending'),
            self.check('properties.protectionStatus', 'Healthy'),
            self.check('resourceGroup', '{rg}')
        ])

        self.kwargs['item1_fullname'] = item1_json['name']

        self.cmd('backup item show -g {rg} -v {vault} -c {container1_fullname} -n {item1_fullname}', checks=[
            self.check('properties.friendlyName', '{item1}'),
            self.check('properties.protectedItemHealthStatus', 'NotReachable'),
            self.check('properties.protectionState', 'IRPending'),
            self.check('properties.protectionStatus', 'Healthy'),
            self.check('resourceGroup', '{rg}')
        ])

        self.cmd('backup item list -g {rg} -v {vault} -c {container1}', checks=[
            #self.check("length(@)", 1),
            self.check("length([?properties.friendlyName == '{item1}'])", 1)
        ])

        self.cmd('backup item list -g {rg} -v {vault} -c {container1_fullname}', checks=[
            #self.check("length(@)", 1),
            self.check("length([?properties.friendlyName == '{item1}'])", 1)
        ])

        self.cmd('backup item list -g {rg} -v {vault} -c {container2}', checks=[
            self.check("length(@)", 1),
            self.check("length([?properties.friendlyName == '{item2}'])", 1)
        ])

        self.cmd('backup item list -g {rg} -v {vault}', checks=[
            #self.check("length(@)", 2),
            self.check("length([?properties.friendlyName == '{item1}'])", 1),
            self.check("length([?properties.friendlyName == '{item2}'])", 1)
        ])

        item1_json = self.cmd('backup item show -g {rg} -v {vault} -c {container1} -n {item1}').get_output_in_json()
        self.assertIn(policy_name.lower(), item1_json['properties']['policyId'].lower())