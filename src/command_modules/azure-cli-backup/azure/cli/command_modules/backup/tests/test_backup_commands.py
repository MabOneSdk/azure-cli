# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import json
from datetime import datetime, timedelta

from azure.cli.testsdk import ScenarioTest, JMESPathCheck, JMESPathCheckGreaterThan, JMESPathCheckExists, ResourceGroupPreparer, StorageAccountPreparer
from .preparers import VaultPreparer, VMPreparer, ItemPreparer, PolicyPreparer, RPPreparer

from azure.mgmt.recoveryservices.models import StorageModelType

class BackupTests(ScenarioTest):
    def _get_first_if_list(self, json_response):
        json_obj = None
        if isinstance(json_response, list):
            if len(json_response) > 0:
                json_obj = json_response[0]
        else:
            json_obj = json_response
        return json_obj

    def _get_vm_version(self, vm_type):
        if vm_type == 'Microsoft.Compute/virtualMachines':
            return 'Compute'
        elif vm_type == 'Microsoft.ClassicCompute/virtualMachines':
            return 'Classic'

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer()
    @StorageAccountPreparer()
    def test_backup_restore(self, resource_group, resource_group_location, vault_name, vm_name, storage_account):
        # Test Flags
        do_enable_protection = True
        do_get_container = True
        do_get_item = True
        do_trigger_backup = True
        do_get_recovery_point = True
        do_trigger_restore = True
        do_disable_protection = True

        vault_json = self.cmd('az backup vault show -n {} -g {}'.format(vault_name, resource_group)).get_output_in_json()
        vault_json = json.dumps(vault_json)

        if do_enable_protection:
            # Enable Protection
            policy_json = self.cmd('az backup policy list --vault \'{}\''.format(vault_json), checks=[
                JMESPathCheck('[0].name', 'DefaultPolicy'),
                JMESPathCheck('[0].resourceGroup', resource_group)
            ]).get_output_in_json()
            policy_json = json.dumps(self._get_first_if_list(policy_json))
            vm_json = self.cmd('az vm show -n {} -g {}'.format(vm_name, resource_group)).get_output_in_json()
            vm_json = json.dumps(vm_json)
            enable_protection_job_json = self.cmd('az backup protection enable-for-vm --policy \'{}\' --vault \'{}\' --vm \'{}\''
                                                  .format(policy_json, vault_json, vm_json)).get_output_in_json()
            enable_protection_job_json = json.dumps(enable_protection_job_json)
            self.cmd('az backup job wait --job \'{}\''.format(enable_protection_job_json))

        if do_get_container:
            # Get Container
            container_json = self.cmd('az backup container show --container-name \'{}\' --vault \'{}\''
                                      .format(vm_name, vault_json)).get_output_in_json()
            container_json = json.dumps(container_json)

        if do_get_item:
            # Get Item
            items_json = self.cmd('az backup item list --container \'{}\''
                                 .format(container_json)).get_output_in_json()
            item_json = json.dumps(self._get_first_if_list(items_json))

        if do_trigger_backup:
            # Trigger Backup
            retain_date = datetime.utcnow() + timedelta(days=30)
            trigger_backup_job_json = self.cmd('az backup protection backup-now --backup-item \'{}\' --retain-until {}'
                                               .format(item_json, retain_date.strftime('%d-%m-%Y'))).get_output_in_json()
            trigger_backup_job_json = json.dumps(trigger_backup_job_json)
            self.cmd('az backup job wait --job \'{}\''.format(trigger_backup_job_json))

        if do_get_recovery_point:
            # Get Recovery Point
            recovery_points_json = self.cmd('az backup recoverypoint list --backup-item \'{}\''
                                            .format(item_json)).get_output_in_json()
            recovery_point_json = json.dumps(self._get_first_if_list(recovery_points_json))
        
        if do_trigger_restore:
            # Trigger Restore
            trigger_restore_job_json = self.cmd('az backup restore disks --recovery-point \'{}\' --destination-storage-account {} --destination-storage-account-resource-group {}'
                                                .format(recovery_point_json, storage_account, resource_group)).get_output_in_json()
            trigger_restore_job_json = json.dumps(trigger_restore_job_json)
            self.cmd('az backup job wait --job \'{}\''.format(trigger_restore_job_json))

        if do_disable_protection:
            # Disable Protection
            disable_protection_job_json = self.cmd('az backup protection disable --backup-item \'{}\' --yes'
                                                   .format(item_json)).get_output_in_json()
            disable_protection_job_json = json.dumps(disable_protection_job_json)
            self.cmd('az backup job wait --job \'{}\''.format(disable_protection_job_json))

    @ResourceGroupPreparer(parameter_name='sa_rg')
    @StorageAccountPreparer(resource_group_parameter_name='sa_rg')
    def test_backup_adhoc(self, storage_account, sa_rg):
        resource_group = 'clitest.rghhpafaki7aj2kmdr4oefm2oc3g2n4ylngaybkba2i2b6dpjj2q7hjptd3k46yccsd'
        vm_name = 'clitest-vm23wmz'
        vault_name = 'clitest-vault63alquyh3vy'

        # Get Vault
        vault_json = self.cmd('az backup vault show -n {} -g {}'.format(vault_name, resource_group)).get_output_in_json()
        vault_json = json.dumps(vault_json)

        # Get Container
        container_json = self.cmd('az backup container show --container-name \'{}\' --vault \'{}\''
                                    .format(vm_name, vault_json)).get_output_in_json()
        container_json = json.dumps(container_json)

        # Get Item
        items_json = self.cmd('az backup item list --container \'{}\''
                                .format(container_json)).get_output_in_json()
        item_json = json.dumps(self._get_first_if_list(items_json))

        # Get Recovery Point
        recovery_points_json = self.cmd('az backup recoverypoint list --backup-item \'{}\''
                                        .format(item_json)).get_output_in_json()
        recovery_point_json = json.dumps(self._get_first_if_list(recovery_points_json))

        # Trigger Restore
        trigger_restore_job_json = self.cmd('az backup restore disks --recovery-point \'{}\' --destination-storage-account {} --destination-storage-account-resource-group {}'
                                            .format(recovery_point_json, storage_account, sa_rg)).get_output_in_json()
        trigger_restore_job_json = json.dumps(trigger_restore_job_json)
        self.cmd('az backup job wait --job \'{}\''.format(trigger_restore_job_json))

    @ResourceGroupPreparer()
    @VaultPreparer(parameter_name='vault1')
    @VaultPreparer(parameter_name='vault2')
    def test_vault_commands(self, resource_group, resource_group_location, vault1, vault2):
        vault3 = self.create_random_name('clitest-vault', 50)
        self.cmd('az backup vault create -n {} -g {} -l {}'.format(vault3, resource_group, resource_group_location), checks=[
            JMESPathCheck('name', vault3),
            JMESPathCheck('resourceGroup', resource_group),
            JMESPathCheck('location', resource_group_location),
            JMESPathCheck('properties.provisioningState', 'Succeeded')
        ])

        self.cmd('az backup vault list', checks=[
            JMESPathCheck("length([?resourceGroup == '{}'])".format(resource_group), 3),
            JMESPathCheck("length([?name == '{}'])".format(vault1), 1),
            JMESPathCheck("length([?name == '{}'])".format(vault2), 1),
            JMESPathCheck("length([?name == '{}'])".format(vault3), 1)
        ])

        self.cmd('az backup vault list -g {}'.format(resource_group), checks=[
            JMESPathCheck("length(@)", 3),
            JMESPathCheck("length([?name == '{}'])".format(vault1), 1),
            JMESPathCheck("length([?name == '{}'])".format(vault2), 1),
            JMESPathCheck("length([?name == '{}'])".format(vault3), 1)
        ])

        storage_model_types = [e.value for e in StorageModelType]
        vault_properties = self.cmd('az backup vault get-backup-properties -n {} -g {}'.format(vault1, resource_group), checks=[
            JMESPathCheckExists("contains({}, storageModelType)".format(storage_model_types)),
            JMESPathCheck('storageTypeState', 'Unlocked'),
            JMESPathCheck('resourceGroup', resource_group)
        ]).get_output_in_json()

        if vault_properties['storageModelType'] == StorageModelType.geo_redundant.value:
            new_storage_model = StorageModelType.locally_redundant.value
        else:
            new_storage_model = StorageModelType.geo_redundant.value

        self.cmd('az backup vault set-backup-properties -n {} -g {} --backup-storage-redundancy {}'
                 .format(vault1, resource_group, new_storage_model))

        self.cmd('az backup vault get-backup-properties -n {} -g {}'.format(vault1, resource_group), checks=[
            JMESPathCheck('storageModelType', new_storage_model)
        ])

        self.cmd('az backup vault delete -n {} -g {} -y'.format(vault3, resource_group))

        self.cmd('az backup vault list', checks=[
            JMESPathCheck("length([?resourceGroup == '{}'])".format(resource_group), 2),
            JMESPathCheck("length([?name == '{}'])".format(vault1), 1),
            JMESPathCheck("length([?name == '{}'])".format(vault2), 1)
        ])

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer(parameter_name='vm1')
    @VMPreparer(parameter_name='vm2')
    @ItemPreparer(vm_parameter_name='vm1')
    @ItemPreparer(vm_parameter_name='vm2')
    def test_container_commands(self, resource_group, resource_group_location, vault_name, vm1, vm2):
        vault_json = json.dumps(self.cmd('az backup vault show -n {} -g {}'.format(vault_name, resource_group)).get_output_in_json())

        container_json = self.cmd('az backup container show --container-name \'{}\' --vault \'{}\''.format(vm1, vault_json), checks=[
            JMESPathCheck('properties.friendlyName', vm1),
            JMESPathCheck('properties.healthStatus', 'Healthy'),
            JMESPathCheck('properties.registrationStatus', 'Registered'),
            JMESPathCheck('properties.resourceGroup', resource_group),
            JMESPathCheck('resourceGroup', resource_group)
        ]).get_output_in_json()

        vm1_json = self.cmd('az vm show -n {} -g {}'.format(vm1, resource_group)).get_output_in_json()

        assert vault_name.lower() in container_json['id'].lower()
        assert vm1.lower() in container_json['name'].lower()
        assert vm1.lower() in container_json['properties']['virtualMachineId'].lower()
        assert container_json['properties']['virtualMachineVersion'] == self._get_vm_version(vm1_json['type'])

        self.cmd('az backup container list --vault \'{}\''.format(vault_json), checks=[
            JMESPathCheck("length(@)", 2),
            JMESPathCheck("length([?properties.friendlyName == '{}'])".format(vm1), 1),
            JMESPathCheck("length([?properties.friendlyName == '{}'])".format(vm2), 1)
        ])

    @ResourceGroupPreparer()
    @VaultPreparer()
    @PolicyPreparer(parameter_name='policy1')
    @PolicyPreparer(parameter_name='policy2')
    @VMPreparer(parameter_name='vm1')
    @VMPreparer(parameter_name='vm2')
    @ItemPreparer(vm_parameter_name='vm1')
    @ItemPreparer(vm_parameter_name='vm2')
    def test_policy_commands(self, resource_group, resource_group_location, vault_name, policy1, policy2, vm1, vm2):
        vault_json = json.dumps(self.cmd('az backup vault show -n {} -g {}'.format(vault_name, resource_group)).get_output_in_json())

        policy3 = self.create_random_name('clitest-policy', 24)
        default_policy = 'DefaultPolicy'
        default_policy_json = json.dumps(self.cmd('az backup policy show --policy-name {} --vault \'{}\''
                                                  .format(default_policy, vault_json)).get_output_in_json())

        policy1_json = self.cmd('az backup policy show --policy-name {} --vault \'{}\''.format(policy1, vault_json), checks=[
            JMESPathCheck('name', policy1),
            JMESPathCheck('resourceGroup', resource_group)
        ]).get_output_in_json()

        self.cmd('az backup policy list --vault \'{}\''.format(vault_json), checks=[
            JMESPathCheck("length(@)", 3),
            JMESPathCheck("length([?name == '{}'])".format(default_policy), 1),
            JMESPathCheck("length([?name == '{}'])".format(policy1), 1),
            JMESPathCheck("length([?name == '{}'])".format(policy2), 1)
        ])
        
        self.cmd('az backup policy list-associated-items --policy \'{}\''.format(default_policy_json), checks=[
            JMESPathCheck("length(@)", 2),
            JMESPathCheck("length([?properties.friendlyName == '{}'])".format(vm1), 1),
            JMESPathCheck("length([?properties.friendlyName == '{}'])".format(vm2), 1)
        ])
        
        policy1_json['name'] = policy3
        policy1_json = json.dumps(policy1_json)

        self.cmd('az backup policy update --policy \'{}\''
                 .format(policy1_json), checks=[
            JMESPathCheck('name', policy3),
            JMESPathCheck('resourceGroup', resource_group)
        ])

        self.cmd('az backup policy list --vault \'{}\''.format(vault_json), checks=[
            JMESPathCheck("length(@)", 4),
            JMESPathCheck("length([?name == '{}'])".format(default_policy), 1),
            JMESPathCheck("length([?name == '{}'])".format(policy1), 1),
            JMESPathCheck("length([?name == '{}'])".format(policy2), 1),
            JMESPathCheck("length([?name == '{}'])".format(policy3), 1)
        ])

        self.cmd('az backup policy delete --policy \'{}\''.format(policy1_json))

        self.cmd('az backup policy list --vault \'{}\''.format(vault_json), checks=[
            JMESPathCheck("length(@)", 3),
            JMESPathCheck("length([?name == '{}'])".format(default_policy), 1),
            JMESPathCheck("length([?name == '{}'])".format(policy1), 1),
            JMESPathCheck("length([?name == '{}'])".format(policy2), 1)
        ])

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer(parameter_name='vm1')
    @VMPreparer(parameter_name='vm2')
    @ItemPreparer(vm_parameter_name='vm1')
    @ItemPreparer(vm_parameter_name='vm2')
    @PolicyPreparer()
    def test_item_commands(self, resource_group, resource_group_location, vault_name, vm1, vm2, policy_name):
        vault_json = json.dumps(self.cmd('az backup vault show -n {} -g {}'
                                         .format(vault_name, resource_group)).get_output_in_json())
        container1_json = json.dumps(self.cmd('az backup container show --container-name \'{}\' --vault \'{}\''
                                             .format(vm1, vault_json)).get_output_in_json())
        container2_json = json.dumps(self.cmd('az backup container show --container-name \'{}\' --vault \'{}\''
                                             .format(vm2, vault_json)).get_output_in_json())
        
        default_policy = 'DefaultPolicy'

        item1_json = self.cmd('az backup item show --container \'{}\' --item-name {}'
                             .format(container1_json, vm1), checks=[
            JMESPathCheck('properties.friendlyName', vm1),
            JMESPathCheck('properties.healthStatus', 'Passed'),
            JMESPathCheck('properties.protectionState', 'IRPending'),
            JMESPathCheck('properties.protectionStatus', 'Healthy'),
            JMESPathCheck('resourceGroup', resource_group)
        ]).get_output_in_json()

        assert vault_name.lower() in item1_json['id'].lower()
        assert vm1.lower() in item1_json['name'].lower()
        assert vm1.lower() in item1_json['properties']['sourceResourceId'].lower()
        assert vm1.lower() in item1_json['properties']['virtualMachineId'].lower()
        assert default_policy.lower() in item1_json['properties']['policyId'].lower()

        self.cmd('az backup item list --container \'{}\''
                 .format(container1_json), checks=[
            JMESPathCheck("length(@)", 1),
            JMESPathCheck("length([?properties.friendlyName == '{}'])".format(vm1), 1)
        ])

        self.cmd('az backup item list --container \'{}\''
                 .format(container2_json), checks=[
            JMESPathCheck("length(@)", 1),
            JMESPathCheck("length([?properties.friendlyName == '{}'])".format(vm2), 1)
        ])

        policy_json = json.dumps(self.cmd('az backup policy show --policy-name \'{}\' --vault \'{}\''
                                          .format(policy_name, vault_json)).get_output_in_json())

        self.cmd('az backup item update-policy --backup-item \'{}\' --policy \'{}\''
                 .format(json.dumps(item1_json), policy_json), checks=[
            JMESPathCheck("properties.entityFriendlyName", vm1),
            JMESPathCheck("properties.operation", "ConfigureBackup"),
            JMESPathCheck("properties.status", "Completed"),
            JMESPathCheck("resourceGroup", resource_group)
        ])

        item1_json = self.cmd('az backup item show --container \'{}\' --item-name {}'
                             .format(container1_json, vm1)).get_output_in_json()
        assert policy_name.lower() in item1_json['properties']['policyId'].lower()

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer()
    @ItemPreparer()
    @RPPreparer()
    @RPPreparer()
    def test_rp_commands(self, resource_group, resource_group_location, vault_name, vm_name):
        vault_json = json.dumps(self.cmd('az backup vault show -n {} -g {}'
                                         .format(vault_name, resource_group)).get_output_in_json())
        container_json = json.dumps(self.cmd('az backup container show --container-name \'{}\' --vault \'{}\''
                                             .format(vm_name, vault_json)).get_output_in_json())
        item_json = json.dumps(self.cmd('az backup item show --container \'{}\' --item-name {}'
                             .format(container_json, vm_name)).get_output_in_json())
        rps_json = self.cmd('az backup recoverypoint list --backup-item \'{}\''
                 .format(item_json), checks=[
            JMESPathCheck("length(@)", 2)
        ]).get_output_in_json()

        rp1_name = rps_json[0]['name']
        rp1_json = self.cmd('az backup recoverypoint show --backup-item \'{}\' --id {}'
                 .format(item_json, rp1_name), checks=[
            JMESPathCheck("name", rp1_name),
            JMESPathCheck("resourceGroup", resource_group)
        ]).get_output_in_json()
        assert vault_name.lower() in rp1_json['id'].lower()
        assert vm_name.lower() in rp1_json['id'].lower()

        rp2_name = rps_json[1]['name']
        rp2_json = self.cmd('az backup recoverypoint show --backup-item \'{}\' --id {}'
                 .format(item_json, rp2_name), checks=[
            JMESPathCheck("name", rp2_name),
            JMESPathCheck("resourceGroup", resource_group)
        ]).get_output_in_json()
        assert vault_name.lower() in rp2_json['id'].lower()
        assert vm_name.lower() in rp2_json['id'].lower()

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer()
    def test_protection_commands(self, resource_group, resource_group_location, vault_name, vm_name):
        vault_json = json.dumps(self.cmd('az backup vault show -n {} -g {}'
                                         .format(vault_name, resource_group)).get_output_in_json())
        policy_json = json.dumps(self.cmd('az backup policy show --policy-name {} --vault \'{}\''
                                         .format('DefaultPolicy', vault_json)).get_output_in_json())
        vm_json = json.dumps(self.cmd('az vm show -n {} -g {}'.format(vm_name, resource_group)).get_output_in_json())
        
        self.cmd('az backup protection enable-for-vm --policy \'{}\' --vault \'{}\' --vm \'{}\''
                 .format(policy_json, vault_json, vm_json), checks=[
            JMESPathCheck("properties.entityFriendlyName", vm_name),
            JMESPathCheck("properties.operation", "ConfigureBackup"),
            JMESPathCheck("properties.status", "Completed"),
            JMESPathCheck("resourceGroup", resource_group)
        ])

        container_json = json.dumps(self.cmd('az backup container show --container-name \'{}\' --vault \'{}\''
                                            .format(vm_name, vault_json)).get_output_in_json())
        item_json = json.dumps(self.cmd('az backup item show --item-name \'{}\' --container \'{}\''
                                       .format(vm_name, container_json)).get_output_in_json())

        self.cmd('az backup protection disable --backup-item \'{}\' --yes'
                 .format(item_json), checks=[
            JMESPathCheck("properties.entityFriendlyName", vm_name),
            JMESPathCheck("properties.operation", "DisableBackup"),
            JMESPathCheck("properties.status", "Completed"),
            JMESPathCheck("resourceGroup", resource_group)
        ])

        self.cmd('az backup item show --item-name \'{}\' --container \'{}\''
                 .format(vm_name, container_json), checks=[
            JMESPathCheck("properties.friendlyName", vm_name),
            JMESPathCheck("properties.protectionState", "ProtectionStopped"),
            JMESPathCheck("resourceGroup", resource_group)
        ])

        self.cmd('az backup protection disable --backup-item \'{}\' --delete-backup-data true --yes'
                 .format(item_json), checks=[
            JMESPathCheck("properties.entityFriendlyName", vm_name),
            JMESPathCheck("properties.operation", "DeleteBackupData"),
            JMESPathCheck("properties.status", "Completed"),
            JMESPathCheck("resourceGroup", resource_group)
        ])

        self.cmd('az backup container list --vault \'{}\''
                 .format(vault_json), checks=[
            JMESPathCheck("length(@)", 0)
        ])

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer()
    @ItemPreparer()
    @RPPreparer()
    @StorageAccountPreparer()
    def test_restore_commands(self, resource_group, resource_group_location, vault_name, vm_name, storage_account):
        vault_json = json.dumps(self.cmd('az backup vault show -n {} -g {}'
                                         .format(vault_name, resource_group)).get_output_in_json())
        container_json = json.dumps(self.cmd('az backup container show --container-name \'{}\' --vault \'{}\''
                                             .format(vm_name, vault_json)).get_output_in_json())
        item_json = json.dumps(self.cmd('az backup item show --container \'{}\' --item-name {}'
                                        .format(container_json, vm_name)).get_output_in_json())
        rps_json = self.cmd('az backup recoverypoint list --backup-item \'{}\''
                            .format(item_json)).get_output_in_json()

        rp1_name = rps_json[0]['name']
        rp1_json = json.dumps(self.cmd('az backup recoverypoint show --backup-item \'{}\' --id {}'
                            .format(item_json, rp1_name)).get_output_in_json())

        # Trigger Restore
        trigger_restore_job_json = self.cmd('az backup restore disks --recovery-point \'{}\' --destination-storage-account {} --destination-storage-account-resource-group {}'
                                            .format(rp1_json, storage_account, resource_group), checks=[
            JMESPathCheck("properties.entityFriendlyName", vm_name),
            JMESPathCheck("properties.operation", "Restore"),
            JMESPathCheck("properties.status", "InProgress"),
            JMESPathCheck("resourceGroup", resource_group)
        ]).get_output_in_json()
        trigger_restore_job_id = trigger_restore_job_json['name']
        trigger_restore_job_json = json.dumps(trigger_restore_job_json)
        self.cmd('az backup job wait --job \'{}\''.format(trigger_restore_job_json))

        trigger_restore_job_details = self.cmd('az backup job show --job-id {} --vault \'{}\''
                 .format(trigger_restore_job_id, vault_json), checks=[
            JMESPathCheck("properties.entityFriendlyName", vm_name),
            JMESPathCheck("properties.operation", "Restore"),
            JMESPathCheck("properties.status", "Completed"),
            JMESPathCheck("resourceGroup", resource_group)
        ]).get_output_in_json()

        assert trigger_restore_job_details['properties']['extendedInfo']['propertyBag']['Target Storage Account Name'] == storage_account

        restore_container = trigger_restore_job_details['properties']['extendedInfo']['propertyBag']['Config Blob Container Name']
        restore_blob = trigger_restore_job_details['properties']['extendedInfo']['propertyBag']['Config Blob Name']

        self.cmd('az storage blob exists --account-name {} -c {} -n {}'
                 .format(storage_account, restore_container, restore_blob), checks=[
            JMESPathCheck("exists", True)
        ])

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer()
    @ItemPreparer()
    @RPPreparer()
    @StorageAccountPreparer()
    def test_job_commands(self, resource_group, resource_group_location, vault_name, vm_name, storage_account):
        vault_json = json.dumps(self.cmd('az backup vault show -n {} -g {}'
                                         .format(vault_name, resource_group)).get_output_in_json())
        container_json = json.dumps(self.cmd('az backup container show --container-name \'{}\' --vault \'{}\''
                                             .format(vm_name, vault_json)).get_output_in_json())
        item_json = json.dumps(self.cmd('az backup item show --container \'{}\' --item-name {}'
                                        .format(container_json, vm_name)).get_output_in_json())
        rps_json = self.cmd('az backup recoverypoint list --backup-item \'{}\''
                            .format(item_json)).get_output_in_json()
        rp_json = json.dumps(rps_json[0])

        trigger_restore_job_json = self.cmd('az backup restore disks --recovery-point \'{}\' --destination-storage-account {} --destination-storage-account-resource-group {}'
                                            .format(rp_json, storage_account, resource_group)).get_output_in_json()
        trigger_restore_job_id = trigger_restore_job_json['name']
        trigger_restore_job_json = json.dumps(trigger_restore_job_json)

        self.cmd('az backup job show --job-id {} --vault \'{}\''
                 .format(trigger_restore_job_id, vault_json), checks=[
            JMESPathCheck("name", trigger_restore_job_id),
            JMESPathCheck("properties.entityFriendlyName", vm_name),
            JMESPathCheck("properties.operation", "Restore"),
            JMESPathCheck("properties.status", "InProgress"),
            JMESPathCheck("resourceGroup", resource_group)
        ])

        self.cmd('az backup job list --vault \'{}\''.format(vault_json), checks=[
            JMESPathCheck("length([?name == '{}'])".format(trigger_restore_job_id), 1)
        ])

        self.cmd('az backup job list --vault \'{}\' --status InProgress'.format(vault_json), checks=[
            JMESPathCheck("length([?name == '{}'])".format(trigger_restore_job_id), 1)
        ])

        self.cmd('az backup job list --vault \'{}\' --operation Restore'.format(vault_json), checks=[
            JMESPathCheck("length([?name == '{}'])".format(trigger_restore_job_id), 1)
        ])

        self.cmd('az backup job list --vault \'{}\' --operation Restore --status InProgress'.format(vault_json), checks=[
            JMESPathCheck("length([?name == '{}'])".format(trigger_restore_job_id), 1)
        ])

        self.cmd('az backup job wait --job \'{}\' --timeout 60'.format(trigger_restore_job_json))
        self.cmd('az backup job show --job-id {} --vault \'{}\''
                 .format(trigger_restore_job_id, vault_json), checks=[
            JMESPathCheck("properties.status", "InProgress")
        ])

        self.cmd('az backup job stop --job \'{}\''.format(trigger_restore_job_json))

        canceled_job = self.cmd('az backup job show --job-id {} --vault \'{}\''
                 .format(trigger_restore_job_id, vault_json)).get_output_in_json()

        canceled_job_status = canceled_job['properties']['status']

        assert canceled_job_status == 'Cancelling' or canceled_job_status == 'Cancelled'