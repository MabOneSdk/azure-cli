# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import json
from datetime import datetime, timedelta
import unittest

import azure.cli.command_modules.backup.tests.latest.test_backup_commands_wl_help as wl_help

from azure.cli.testsdk import ScenarioTest, JMESPathCheckExists, ResourceGroupPreparer, \
    StorageAccountPreparer
from azure.mgmt.recoveryservicesbackup.models import StorageType

from .preparers import VaultPreparer, VMPreparer, ItemPreparer, PolicyPreparer, RPPreparer


id_sql = '/subscriptions/da364f0f-307b-41c9-9d47-b7413ec45535/resourceGroups/pstestwlRG1bca8/providers/Microsoft.Compute/virtualMachines/pstestwlvm1bca8'
id_hana = '/subscriptions/e3d2d341-4ddb-4c5d-9121-69b7e719485e/resourceGroups/IDCDemo/providers/Microsoft.Compute/virtualMachines/HANADemoIDC3'
item_id_sql = '/Subscriptions/da364f0f-307b-41c9-9d47-b7413ec45535/resourceGroups/pstestwlRG1bca8/providers/Microsoft.RecoveryServices/vaults/pstestwlRSV1bca8/backupFabrics/Azure/protectionContainers/vmappcontainer;compute;pstestwlrg1bca8;pstestwlvm1bca8/protectedItems/sqldatabase;mssqlserver;testdb1'
item_id_hana = '/Subscriptions/e3d2d341-4ddb-4c5d-9121-69b7e719485e/resourceGroups/IDCDemo/providers/Microsoft.RecoveryServices/vaults/IDCDemoVault/backupFabrics/Azure/protectionContainers/vmappcontainer;compute;IDCDemo;HANADemoIDC3/protectedItems/sqldatabase;mssqlserver;testdb1'
sub_sql = 'da364f0f-307b-41c9-9d47-b7413ec45535'
sub_hana = 'e3d2d341-4ddb-4c5d-9121-69b7e719485e'
rg_sql = 'pstestwlRG1bca8'
rg_hana = 'IDCDemo'
vault_sql = 'pstestwlRSV1bca8'
vault_hana = 'IDCDemoVault'
container_sql = 'VMAppContainer;Compute;pstestwlRG1bca8;pstestwlvm1bca8'
container_hana = 'VMAppContainer;Compute;IDCDemo;HANADemoIDC3'
container_friendly_sql = 'pstestwlvm1bca8'
container_friendly_hana = 'HANADemoIDC3'
item1_sql = 'testdb1'
item2_sql = 'msdb'
item1_hana = 'model'
item2_hana = 'msdb'

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

        wl_help.test_backup_scenario(self, resource_group, vault_name, vm_name, storage_account)

    @ResourceGroupPreparer()
    @VaultPreparer(parameter_name='vault1')
    @VaultPreparer(parameter_name='vault2')
    def test_backup_vault(self, resource_group, resource_group_location, vault1, vault2):

        wl_help.test_backup_vault(self, resource_group, resource_group_location, vault1, vault2)

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer(parameter_name='vm1')
    @VMPreparer(parameter_name='vm2')
    @ItemPreparer(vm_parameter_name='vm1')
    @ItemPreparer(vm_parameter_name='vm2')
    def test_backup_container(self, resource_group, vault_name, vm1, vm2):

        wl_help.test_backup_container(self, resource_group, vault_name, vm1, vm2)

    def test_backup_wl_sql_container(self, container_name1=container_sql, container_name2=container_friendly_sql,
                                     resource_group=rg_sql, vault_name=vault_sql, workload_type='MSSQL',
                                     subscription=sub_sql, id=id_sql):

        wl_help.test_backup_wl_container(self, container_name1, container_name2, resource_group, vault_name,
                                         workload_type, subscription, id)

    def test_backup_wl_hana_container(self, container_name1=container_hana, container_name2=container_friendly_hana,
                                      resource_group=rg_hana, vault_name=vault_hana, workload_type='SAPHANA',
                                      subscription=sub_hana, id=id_hana):

        wl_help.test_backup_wl_container(self, container_name1, container_name2, resource_group, vault_name,
                                         workload_type, subscription, id)

    @ResourceGroupPreparer()
    @VaultPreparer()
    @PolicyPreparer(parameter_name='policy1')
    @PolicyPreparer(parameter_name='policy2')
    @VMPreparer(parameter_name='vm1')
    @VMPreparer(parameter_name='vm2')
    @ItemPreparer(vm_parameter_name='vm1')
    @ItemPreparer(vm_parameter_name='vm2')
    def test_backup_policy(self, resource_group, vault_name, policy1, policy2, vm1, vm2):

        wl_help.test_backup_policy(self, resource_group, vault_name, policy1, policy2, vm1, vm2)

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer(parameter_name='vm1')
    @VMPreparer(parameter_name='vm2')
    @ItemPreparer(vm_parameter_name='vm1')
    @ItemPreparer(vm_parameter_name='vm2')
    @PolicyPreparer()
    def test_backup_item(self, resource_group, vault_name, vm1, vm2, policy_name):

        wl_help.test_backup_item(self, resource_group, vault_name, vm1, vm2, policy_name)

    def test_backup_wl_sql_item(self, container_name1=container_sql, container_name2=container_friendly_sql,
                                resource_group=rg_sql, vault_name=vault_sql, policy_name='HourlyLogBackup',
                                workload_type='MSSQL', subscription=sub_sql, item1=item1_sql, id=id_sql, type='SQLDataBase',
                                item_id=item_id_sql):

        wl_help.test_backup_wl_item(self, container_name1, container_name2, resource_group, vault_name, policy_name,
                                    workload_type, subscription, item1, id, type, item_id)

    def test_backup_wl_hana_item(self, container_name1=container_hana, container_name2=container_friendly_hana,
                                 resource_group=rg_hana, vault_name=vault_hana, policy_name='HourlyLogBackup',
                                 workload_type='SAPHANA', subscription=sub_hana, item1=item1_hana, id=id_hana, type='HANADataBase',
                                 item_id=item_id_hana):

        wl_help.test_backup_wl_item(self, container_name1, container_name2, resource_group, vault_name, policy_name,
                                    workload_type, subscription, item1, id, type, item_id)

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer()
    @ItemPreparer()
    @RPPreparer()
    @RPPreparer()
    def test_backup_rp(self, resource_group, vault_name, vm_name):

        wl_help.test_backup_rp(self, resource_group, vault_name, vm_name)

    def test_backup_wl_sql_rp(self, container_name=container_sql, resource_group=rg_sql,vault_name=vault_sql,
                              item_name=item1_sql, workload_type='MSSQL', subscription=sub_sql, type='SQLDataBase',
                              container_name2=container_friendly_sql, policy_name='HourlyLogBackup', id=id_sql,
                              item_id=item_id_sql):

        wl_help.test_backup_wl_rp(self, container_name, resource_group, vault_name, item_name, workload_type, subscription,
                                  type, container_name2, policy_name, id, item_id)

    def test_backup_wl_hana_rp(self, container_name=container_hana, resource_group=rg_hana, vault_name=vault_hana,
                               item_name=item1_sql, workload_type='SAPHANA', subscription=sub_hana, type='HANADataBase',
                               container_name2=container_friendly_hana, policy_name='HourlyLogBackup', id=id_hana,
                               item_id=item_id_hana):

        wl_help.test_backup_wl_rp(self, container_name, resource_group, vault_name, item_name, workload_type, subscription,
                                  type, container_name2, policy_name, id, item_id)

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer()
    def test_backup_protection(self, resource_group, vault_name, vm_name):

        wl_help.test_backup_protection(self, resource_group, vault_name, vm_name)

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer()
    @ItemPreparer()
    @RPPreparer()
    @StorageAccountPreparer()
    def test_backup_restore(self, resource_group, vault_name, vm_name, storage_account):

        wl_help.test_backup_restore(self, resource_group, vault_name, vm_name, storage_account)

    @ResourceGroupPreparer()
    @VaultPreparer()
    @VMPreparer()
    @ItemPreparer()
    @RPPreparer()
    @StorageAccountPreparer()
    def test_backup_job(self, resource_group, vault_name, vm_name, storage_account):

        wl_help.test_backup_job(self, resource_group, vault_name, vm_name, storage_account)

    def test_backup_protectable_item(self, container_name1='shrac3', container_name2='shrac2', resource_group='shracrg',
                                     vault_name='shracsql', policy_name='HourlyLogBackup'):

        wl_help.test_backup_protectable_item(self, container_name1, container_name2, resource_group, vault_name,
                                             policy_name)
