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

subscription_id = "da364f0f-307b-41c9-9d47-b7413ec45535"
unprotected_afs = "clitestafs"
protected_afs1 = "sarathtestafs"
protected_afs2 = "afstest1"
target_afs = "afstest2"
storage_account = "sarathsa"
resource_group_name = "sarath-rg"
vault_name = "sarath-vault"


class BackupTests(ScenarioTest, unittest.TestCase):
    def test_afs_backup_scenario(self):
        self.kwargs.update({
            'vault': vault_name,
            'subscription_id': subscription_id,
            'item': unprotected_afs,
            'container': storage_account,
            'rg': resource_group_name,
            'type': "AzureStorage"
        })
        self.cmd('backup protection enable-for-azurefileshare -g {rg} -v {vault} --storage-account {container} --azure-file-share {item} -p afspolicy1')

        self.kwargs['retain_date'] = (datetime.utcnow() + timedelta(days=30)).strftime('%d-%m-%Y')

        self.kwargs['job'] = self.cmd('backup protection backup-now -g {rg} -v {vault} -c {container} -i {item} --retain-until {retain_date} --backup-management-type AzureStorage --query name').get_output_in_json()
        self.cmd('backup job wait -g {rg} -v {vault} -n {job}')

        self.kwargs['rp'] = self.cmd('backup recoverypoint list -g {rg} -v {vault} -c {container} -i {item} --backup-management-type AzureStorage --query [0].name').get_output_in_json()

        # Trigger Restore
        self.kwargs['job'] = self.cmd('backup restore restore-azurefileshare -g {rg} -v {vault} -c {container} -i {item} -r {rp} --resolve-conflict Overwrite --restore-mode OriginalLocation --query name').get_output_in_json()
        self.cmd('backup job wait -g {rg} -v {vault} -n {job}')

        # Disable Protection
        self.cmd('backup protection disable -g {rg} -v {vault} -c {container} -i {item} --backup-management-type AzureStorage --delete-backup-data true --yes')

    def test_afs_backup_container(self):
        self.kwargs.update({
            'vault': vault_name,
            'subscription_id': subscription_id,
            'sa1': "chandrikargdiag",
            'sa2': "sarathsa",
            'rg': resource_group_name,
            'type': "AzureStorage"
        })

        container_json = self.cmd('backup container show -n {sa2} -v {vault} -g {rg} --backup-management-type {type}', checks=[
            self.check('properties.friendlyName', '{sa2}'),
            self.check('properties.healthStatus', 'Healthy'),
            self.check('properties.registrationStatus', 'Registered'),
            self.check('resourceGroup', '{rg}')
        ]).get_output_in_json()

        self.kwargs['container_name'] = container_json['name']

        self.cmd('backup container show -n {container_name} -v {vault} -g {rg}', checks=[
            self.check('properties.friendlyName', '{sa2}'),
            self.check('properties.healthStatus', 'Healthy'),
            self.check('properties.registrationStatus', 'Registered'),
            self.check('name', '{container_name}'),
            self.check('resourceGroup', '{rg}')
        ]).get_output_in_json()

        self.cmd('backup container list -v {vault} -g {rg} --backup-management-type {type}', checks=[
            self.check("length(@)", 2),
            self.check("length([?properties.friendlyName == '{sa1}'])", 1),
            self.check("length([?properties.friendlyName == '{sa2}'])", 1)])

    def test_afs_backup_item(self):
        self.kwargs.update({
            'vault': vault_name,
            'subscription_id': subscription_id,
            'item1': protected_afs1,
            'item2': protected_afs2,
            'container': storage_account,
            'rg': resource_group_name,
            'type': "AzureStorage",
            'policy': "afspolicy1",
            'newpolicy': "afsdailypolicy"
        })

        self.kwargs['container1'] = self.cmd('backup container show -g {rg} -v {vault} -n {container} --backup-management-type {type} --query name').get_output_in_json()

        item1_json = self.cmd('backup item show -g {rg} -v {vault} -c {container1} -n {item1}', checks=[
            self.check('properties.friendlyName', '{item1}'),
            self.check('properties.protectionState', 'Protected'),
            self.check('properties.protectionStatus', 'Healthy'),
            self.check('resourceGroup', '{rg}')
        ]).get_output_in_json()

        self.kwargs['item1_fullname'] = item1_json['name']

        self.cmd('backup item show -g {rg} -v {vault} -c {container1} -n {item1_fullname}', checks=[
            self.check('properties.friendlyName', '{item1}'),
            self.check('properties.protectionState', 'Protected'),
            self.check('properties.protectionStatus', 'Healthy'),
            self.check('resourceGroup', '{rg}')
        ])

        self.cmd('backup item list -g {rg} -v {vault} -c {container}', checks=[
            self.check("length(@)", 5),
            self.check("length([?properties.friendlyName == '{item1}'])", 1)
        ])

        self.cmd('backup item list -g {rg} -v {vault} -c {container}', checks=[
            self.check("length(@)", 5),
            self.check("length([?properties.friendlyName == '{item2}'])", 1)
        ])

        self.cmd('backup item list -g {rg} -v {vault} -c {container1}', checks=[
            self.check("length(@)", 5),
            self.check("length([?properties.friendlyName == '{item1}'])", 1)
        ])

        self.cmd('backup item set-policy -g {rg} -v {vault} -c {container1} -n {item1} -p {newpolicy}', checks=[
            self.check("properties.operation", "ConfigureBackup"),
            self.check("properties.status", "Completed"),
            self.check("resourceGroup", '{rg}')
        ])

        item1_json = self.cmd('backup item show -g {rg} -v {vault} -c {container1} -n {item1}').get_output_in_json()
        self.assertIn(self.kwargs['newpolicy'].lower(), item1_json['properties']['policyId'].split('/')[-1].lower())

    def test_afs_backup_rp(self):
        self.kwargs.update({
            'vault': vault_name,
            'subscription_id': subscription_id,
            'item1': protected_afs1,
            'item2': protected_afs2,
            'container': storage_account,
            'rg': resource_group_name,
            'type': "AzureStorage",
        })
        rp_names = self.cmd('backup recoverypoint list -g {rg} -v {vault} -c {container} -i {item1} --backup-management-type {type} --query [].name').get_output_in_json()

        self.kwargs['rp1'] = rp_names[0]

        self.cmd('backup recoverypoint show -g {rg} -v {vault} -c {container} -i {item1} -n {rp1} --backup-management-type {type}', checks=[
            self.check("name", '{rp1}'),
            self.check("resourceGroup", '{rg}')
        ])

        self.kwargs['rp2'] = rp_names[1]

        self.cmd('backup recoverypoint show -g {rg} -v {vault} -c {container} -i {item1} -n {rp2} --backup-management-type {type}', checks=[
            self.check("name", '{rp2}'),
            self.check("resourceGroup", '{rg}')
        ])

    def test_afs_backup_restore(self):
        self.kwargs.update({
            'vault': vault_name,
            'subscription_id': subscription_id,
            'item1': protected_afs1,
            'item2': protected_afs2,
            'container': storage_account,
            'rg': resource_group_name,
            'type': "AzureStorage",
        })

        # full share restore original location

        rp_names = self.cmd('backup recoverypoint list -g {rg} -v {vault} -c {container} -i {item1} --backup-management-type {type} --query [].name').get_output_in_json()
        self.kwargs['rp1'] = rp_names[0]

        trigger_restore_job1_json = self.cmd('backup restore restore-azurefileshare -g {rg} -v {vault} -c {container} -i {item1} -r {rp1} --resolve-conflict Overwrite --restore-mode OriginalLocation', checks=[
            self.check("properties.entityFriendlyName", '{item1}'),
            self.check("properties.operation", "Restore"),
            self.check("properties.status", "InProgress"),
            self.check("resourceGroup", '{rg}')
        ]).get_output_in_json()
        self.kwargs['job1'] = trigger_restore_job1_json['name']
        self.cmd('backup job wait -g {rg} -v {vault} -n {job1}')

        self.cmd('backup job show -g {rg} -v {vault} -n {job1}', checks=[
            self.check("properties.entityFriendlyName", '{item1}'),
            self.check("properties.operation", "Restore"),
            self.check("properties.status", "Completed"),
            self.check("resourceGroup", '{rg}')
        ])

        # full share alternate location

        trigger_restore_job2_json = self.cmd('backup restore restore-azurefileshare -g {rg} -v {vault} -c {container} -i {item1} -r {rp1} --resolve-conflict Overwrite --restore-mode AlternateLocation --target-storage-account {container} --target-file-share {item2} --target-folder folder1', checks=[
            self.check("properties.entityFriendlyName", '{item1}'),
            self.check("properties.operation", "Restore"),
            self.check("properties.status", "InProgress"),
            self.check("resourceGroup", '{rg}')
        ]).get_output_in_json()
        self.kwargs['job2'] = trigger_restore_job2_json['name']
        self.cmd('backup job wait -g {rg} -v {vault} -n {job2}')

        self.cmd('backup job show -g {rg} -v {vault} -n {job2}', checks=[
            self.check("properties.entityFriendlyName", '{item1}'),
            self.check("properties.operation", "Restore"),
            self.check("properties.status", "Completed"),
            self.check("resourceGroup", '{rg}')
        ])

        # item level recovery alternate location

        trigger_restore_job3_json = self.cmd('backup restore restore-azurefiles -g {rg} -v {vault} -c {container} -i {item1} -r {rp1} --resolve-conflict Overwrite --restore-mode AlternateLocation --source-file-type File --source-file-path script.ps1 --target-storage-account {container} --target-file-share {item2} --target-folder folder1', checks=[
            self.check("properties.entityFriendlyName", '{item1}'),
            self.check("properties.operation", "Restore"),
            self.check("properties.status", "InProgress"),
            self.check("resourceGroup", '{rg}')
        ]).get_output_in_json()
        self.kwargs['job3'] = trigger_restore_job3_json['name']
        self.cmd('backup job wait -g {rg} -v {vault} -n {job3}')

        self.cmd('backup job show -g {rg} -v {vault} -n {job3}', checks=[
            self.check("properties.entityFriendlyName", '{item1}'),
            self.check("properties.operation", "Restore"),
            self.check("properties.status", "Completed"),
            self.check("resourceGroup", '{rg}')
        ])

    def test_afs_backup_protection(self):
        self.kwargs.update({
            'vault': vault_name,
            'subscription_id': subscription_id,
            'item': "afs7",
            'container': "sarathafssa4",
            'rg': resource_group_name,
            'type': "AzureStorage",
            'policy': "afspolicy1"
        })

        self.cmd('backup protection enable-for-azurefileshare -g {rg} -v {vault} --storage-account {container} --azure-file-share {item} -p {policy}', checks=[
            self.check("properties.entityFriendlyName", '{item}'),
            self.check("properties.operation", "ConfigureBackup"),
            self.check("properties.status", "Completed"),
            self.check("resourceGroup", '{rg}')
        ]).get_output_in_json()

        item_json = self.cmd('backup item list -g {rg} -v {vault} -c {container} --backup-management-type {type}').get_output_in_json()
        protected_item_count1 = len(item_json)

        self.cmd('backup protection disable -g {rg} -v {vault} -c {container} -i {item} --backup-management-type {type} --yes', checks=[
            self.check("properties.entityFriendlyName", '{item}'),
            self.check("properties.operation", "DisableBackup"),
            self.check("properties.status", "Completed"),
            self.check("resourceGroup", '{rg}')
        ])

        self.cmd('backup item show -g {rg} -v {vault} -c {container} -n {item} --backup-management-type {type}', checks=[
            self.check("properties.friendlyName", '{item}'),
            self.check("properties.protectionState", "ProtectionStopped"),
            self.check("resourceGroup", '{rg}')
        ])

        self.cmd('backup protection disable -g {rg} -v {vault} -c {container} -i {item} --backup-management-type {type} --delete-backup-data true --yes', checks=[
            self.check("properties.entityFriendlyName", '{item}'),
            self.check("properties.operation", "DeleteBackupData"),
            self.check("properties.status", "Completed"),
            self.check("resourceGroup", '{rg}')
        ])

        item_json = self.cmd('backup item list -g {rg} -v {vault} -c {container} --backup-management-type {type}').get_output_in_json()
        protected_item_count2 = len(item_json)

        self.assertTrue(protected_item_count1 == protected_item_count2 + 1)

    def test_afs_backup_policy(self):
        self.kwargs.update({
            'vault': vault_name,
            'subscription_id': subscription_id,
            'item': "sarathtestafs",
            'container': "sarathsa",
            'rg': resource_group_name,
            'type': "AzureStorage",
            'policy': "afspolicy1",
            'policy2': "clitestafspolicy"
        })

        policies_json = self.cmd('backup policy list -g {rg} -v {vault} --backup-management-type {type}').get_output_in_json()
        policy_count1 = len(policies_json)

        self.kwargs['policy1_json'] = self.cmd('backup policy show -g {rg} -v {vault} -n {policy}', checks=[
            self.check("name", '{policy}'),
            self.check("properties.backupManagementType", '{type}'),
            self.check("resourceGroup", '{rg}'),
            self.check("properties.retentionPolicy.dailySchedule.retentionDuration.count", 60),
        ]).get_output_in_json()

        self.kwargs['policy1_json']['name'] = self.kwargs['policy2']
        self.kwargs['policy1_json']['properties']['retentionPolicy']['dailySchedule']['retentionDuration']['count'] = 25
        self.kwargs['policy1_json'] = json.dumps(self.kwargs['policy1_json'])

        self.cmd("backup policy create -g {rg} -v {vault} --policy '{policy1_json}' --name {policy2}")

        self.kwargs['policy2_json'] = self.cmd('backup policy show -g {rg} -v {vault} --n {policy2}', checks=[
            self.check("name", '{policy2}'),
            self.check("properties.backupManagementType", '{type}'),
            self.check("properties.protectedItemsCount", 0),
            self.check("properties.retentionPolicy.dailySchedule.retentionDuration.count", 25),
        ]).get_output_in_json()

        policies_json = self.cmd('backup policy list -g {rg} -v {vault} --backup-management-type {type}').get_output_in_json()
        policy_count2 = len(policies_json)
        
        self.assertTrue(policy_count2 == policy_count1 + 1)

        self.kwargs['policy2_json']['properties']['retentionPolicy']['dailySchedule']['retentionDuration']['count'] = 20
        self.kwargs['policy2_json'] = json.dumps(self.kwargs['policy2_json'])

        self.cmd("backup policy set -g {rg} -v {vault} --policy '{policy2_json}' -n {policy2}")
        self.cmd('backup policy show -g {rg} -v {vault} -n {policy2}', checks=[
            self.check("properties.retentionPolicy.dailySchedule.retentionDuration.count", 20),
        ]).get_output_in_json()
