# coding=utf-8
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from knack.help_files import helps  # pylint: disable=unused-import
# pylint: disable=line-too-long, too-many-lines

helps['backup'] = """
type: group
short-summary: Manage Azure Backups.
"""

helps['backup container'] = """
type: group
short-summary: Resource which houses items or applications to be protected.
"""

helps['backup container list'] = """
type: command
short-summary: List containers registered to a Recovery services vault.
examples:
  - name: List containers registered to a Recovery services vault. (autogenerated)
    text: az backup container list --resource-group MyResourceGroup --vault-name MyVault --backup-management-type AzureIaasVM
    crafted: true
"""

helps['backup container show'] = """
type: command
short-summary: Show details of a container registered to a Recovery services vault.
examples:
  - name: Show details of a container registered to a Recovery services vault. (autogenerated)
    text: az backup container show --name MyContainer --resource-group MyResourceGroup --vault-name MyVault
    crafted: true
"""

helps['backup container unregister'] = """
type: command
short-summary: This command allows Azure Backup to unregister a ‘Backup Container’ so that the underlying 'resource' can be protected to another vault, if required. The existing backup data in this vault should be deleted before 'unregister' can be performed.
examples:
  - name: This command allows Azure Backup to unregister a ‘Backup Container’ so that the underlying 'resource' can be protected to another vault, if required. The existing backup data in this vault should be deleted before 'unregister' can be performed. (autogenerated)
    text: az backup container unregister --container-name MyContainer --resource-group MyResourceGroup --vault-name MyVault --backup-management-type AzureStorage
    crafted: true
"""

helps['backup item'] = """
type: group
short-summary: An item which is already protected or backed up to an Azure Recovery services vault with an associated policy.
"""

helps['backup item list'] = """
type: command
short-summary: List all backed up items within a container.
examples:
  - name: List all backed up items within a container. (autogenerated)
    text: az backup item list --resource-group MyResourceGroup --vault-name MyVault
    crafted: true
"""

helps['backup item set-policy'] = """
type: command
short-summary: Update the policy associated with this item. Use this to change policies of the backup item.
examples:
  - name: Update the policy associated with this item. Use this to change policies of the backup item. (autogenerated)
    text: az backup item set-policy --vault-name MyVault --resource-group MyResourceGroup --container-name MyContainer --name MyItem --policy-name MyPolicy
    crafted: true
"""

helps['backup item show'] = """
type: command
short-summary: Show details of a particular backed up item.
examples:
  - name: Show details of a particular backed up item. (autogenerated)
    text: az backup item show --container-name MyContainer --ids {ids} --name MyBackedUpItem
    crafted: true
  - name: Show details of a particular backed up item. (autogenerated)
    text: az backup item show --container-name MyContainer --name MyBackedUpItem --resource-group MyResourceGroup --vault-name MyVault
    crafted: true
"""

helps['backup job'] = """
type: group
short-summary: Entity which contains details of the job.
"""

helps['backup job list'] = """
type: command
short-summary: List all backup jobs of a Recovery Services vault.
examples:
  - name: List all backup jobs of a Recovery Services vault
    text: az backup job list --resource-group MyResourceGroup --vault-name MyVault
    crafted: true
"""

helps['backup job show'] = """
type: command
short-summary: Show details of a particular job.
examples:
  - name: Show details of a particular job. (autogenerated)
    text: az backup job show --name MyJob --resource-group MyResourceGroup --vault-name MyVault
    crafted: true
"""

helps['backup job stop'] = """
type: command
short-summary: Suspend or terminate a currently running job.
examples:
  - name: Suspend or terminate a currently running job. (autogenerated)
    text: az backup job stop --name MyJob --resource-group MyResourceGroup --vault-name MyVault
    crafted: true
"""

helps['backup job wait'] = """
type: command
short-summary: Wait until either the job completes or the specified timeout value is reached.
examples:
  - name: Wait until either the job completes or the specified timeout value is reached
    text: az backup job wait --name MyJob --resource-group MyResourceGroup --vault-name MyVault
    crafted: true
"""

helps['backup policy'] = """
type: group
short-summary: A backup policy defines when you want to take a backup and for how long you would retain each backup copy.
"""

helps['backup policy delete'] = """
type: command
short-summary: Before you can delete a Backup protection policy, the policy must not have any associated Backup items. To associate another policy with a Backup item, use the backup item set-policy command.
examples:
  - name: Before you can delete a Backup protection policy, the policy must not have any associated Backup items. To associate another policy with a Backup item, use the backup item set-policy command. (autogenerated)
    text: az backup policy delete --name MyBackupPolicy --resource-group MyResourceGroup --vault-name MyVault
    crafted: true
"""

helps['backup policy get-default-for-vm'] = """
type: command
short-summary: Get the default policy with default values to backup a VM.
examples:
  - name: Get the default policy with default values to backup a VM. (autogenerated)
    text: az backup policy get-default-for-vm --resource-group MyResourceGroup --vault-name MyVault
    crafted: true
"""

helps['backup policy list'] = """
type: command
short-summary: List all policies for a Recovery services vault.
examples:
  - name: List all policies for a Recovery services vault. (autogenerated)
    text: az backup policy list --resource-group MyResourceGroup --vault-name MyVault
    crafted: true
"""

helps['backup policy list-associated-items'] = """
type: command
short-summary: List all items protected by a backup policy.
examples:
  - name: List all items protected by a backup policy
    text: az backup policy list-associated-items --name MyBackupPolicy --resource-group MyResourceGroup --vault-name MyVault
    crafted: true
"""

helps['backup policy set'] = """
type: command
short-summary: Update the properties of the backup policy.
examples:
  - name: Update the properties of the backup policy. (autogenerated)
    text: az backup policy set --policy {policy} --resource-group MyResourceGroup --vault-name MyVault
    crafted: true
"""

helps['backup policy show'] = """
type: command
short-summary: Show details of a particular policy.
examples:
  - name: Show details of a particular policy
    text: az backup policy show --name MyBackupPolicy --resource-group MyResourceGroup --vault-name MyVault
    crafted: true
"""

helps['backup policy create'] = """
type: command
short-summary: Creates a new policy for the given BackupManagementType and workloadType
examples:
  - name: Creates a new policy for the given BackupManagementType and workloadType (autogenerated)
    text: az backup policy create --policy {policy} --resource-group MyResourceGroup --vault-name MyVault --name MyPolicy
    crafted: true
"""

helps['backup protection'] = """
type: group
short-summary: Manage protection of your items, enable protection or disable it, or take on-demand backups.
"""

helps['backup protection backup-now'] = """
type: command
short-summary: Perform an on-demand backup of a backed up item.
examples:
  - name: Perform an on-demand backup of a backed up item. (autogenerated)
    text: az backup protection backup-now --container-name MyContainer --item-name MyItem --resource-group MyResourceGroup --retain-until 01-02-2018 --vault-name MyVault
    crafted: true
"""

helps['backup protection check-vm'] = """
type: command
short-summary: Find out whether the virtual machine is protected or not. If protected, it returns the recovery services vault ID, otherwise it returns empty.
examples:
  - name: Find out whether the virtual machine is protected or not. If protected, it returns the recovery services vault ID, otherwise it returns empty. (autogenerated)
    text: az backup protection check-vm --vm-id {vm-id}
    crafted: true
"""

helps['backup protection disable'] = """
type: command
short-summary: Stop protecting a backed up item. Can retain the backed up data forever or choose to delete it.
examples:
  - name: Stop protecting a backed up item. Can retain the backed up data forever or choose to delete it. (autogenerated)
    text: az backup protection disable --container-name MyContainer --delete-backup-data false --item-name MyItem --resource-group MyResourceGroup --vault-name MyVault --yes
    crafted: true
"""

helps['backup protection enable-for-vm'] = """
type: command
short-summary: Start protecting a previously unprotected Azure VM as per the specified policy to a Recovery services vault.
examples:
  - name: Start protecting a previously unprotected Azure VM as per the specified policy to a Recovery services vault. (autogenerated)
    text: az backup protection enable-for-vm --policy-name MyPolicy --resource-group MyResourceGroup --vault-name MyVault --vm myVM
    crafted: true
"""

helps['backup protection enable-for-azurefileshare'] = """
type: command
short-summary: Start protecting a previously unprotected Azure File share within an Azure Storage account as per the specified policy to a Recovery services vault. Provide the Azure File share name and the parent storage account name.
examples:
  - name: Start protecting a previously unprotected Azure File share within an Azure Storage account as per the specified policy to a Recovery services vault. Provide the Azure File share name and the parent storage account name. (autogenerated)
    text: az backup protection enable-for-azurefileshare --policy-name MyPolicy --resource-group MyResourceGroup --vault-name MyVault --storage-account MyStorageAccount --azure-file-share MyAzureFileShare
    crafted: true
"""

helps['backup recoverypoint'] = """
type: group
short-summary: A snapshot of data at that point-of-time, stored in Recovery Services Vault, from which you can restore information.
"""

helps['backup recoverypoint list'] = """
type: command
short-summary: List all recovery points of a backed up item.
examples:
  - name: List all recovery points of a backed up item. (autogenerated)
    text: az backup recoverypoint list --container-name MyContainer --item-name MyItem --resource-group MyResourceGroup --vault-name MyVault
    crafted: true
"""

helps['backup recoverypoint show'] = """
type: command
short-summary: Shows details of a particular recovery point.
examples:
  - name: Shows details of a particular recovery point. (autogenerated)
    text: az backup recoverypoint show --container-name MyContainer --item-name MyItem --name MyRecoveryPoint --resource-group MyResourceGroup --vault-name MyVault
    crafted: true
"""

helps['backup restore'] = """
type: group
short-summary: Restore backed up items from recovery points in a Recovery Services vault.
"""

helps['backup restore files'] = """
type: group
short-summary: Gives access to all files of a recovery point.
"""

helps['backup restore files mount-rp'] = """
type: command
short-summary: Download a script which mounts files of a recovery point.
examples:
  - name: Download a script which mounts files of a recovery point. (autogenerated)
    text: az backup restore files mount-rp --container-name MyContainer --item-name MyItem --resource-group MyResourceGroup --rp-name MyRp --vault-name MyVault
    crafted: true
"""

helps['backup restore files unmount-rp'] = """
type: command
short-summary: Close access to the recovery point.
examples:
  - name: Close access to the recovery point. (autogenerated)
    text: az backup restore files unmount-rp --container-name MyContainer --item-name MyItem --resource-group MyResourceGroup --rp-name MyRp --vault-name MyVault
    crafted: true
"""

helps['backup restore restore-disks'] = """
type: command
short-summary: Restore disks of the backed VM from the specified recovery point.
examples:
  - name: Restore disks of the backed VM from the specified recovery point. (autogenerated)
    text: az backup restore restore-disks --container-name MyContainer --item-name MyItem --resource-group MyResourceGroup --rp-name MyRp --storage-account mystorageaccount --vault-name MyVault
    crafted: true
"""

helps['backup restore restore-azurefileshare'] = """
type: command
short-summary: Restore backed up Azure Workloads in a Recovery services vault to another registered container or to the same container.
examples:
  - name: Restore backed up Azure Workloads in a Recovery services vault to another registered container or to the same container. (autogenerated)
    text: az backup restore restore-azurefileshare --resource-group MyResourceGroup --vault-name MyVault --container-name MyContainer --item-name MyItem --rp-name recoverypoint --resolve-conflict Overwrite --restore-mode OriginalLocation
    crafted: true
"""

helps['backup restore restore-azurefiles'] = """
type: command
short-summary: Restore backed up Azure Workloads in a Recovery services vault to another registered container or to the same container.
examples:
  - name: Restore backed up Azure Workloads in a Recovery services vault to another registered container or to the same container. (autogenerated)
    text: az backup restore restore-azurefiles --resource-group MyResourceGroup --vault-name MyVault --container-name MyContainer --item-name MyItem --rp-name recoverypoint --resolve-conflict Overwrite --restore-mode OriginalLocation --source-file-type File --source-file-path MyPath
    crafted: true
"""

helps['backup vault'] = """
type: group
short-summary: Online storage entity in Azure used to hold data such as backup copies, recovery points and backup policies.
"""

helps['backup vault backup-properties'] = """
type: group
short-summary: Properties of the Recovery Services vault.
"""

helps['backup vault backup-properties set'] = """
type: command
short-summary: Sets backup related properties of the Recovery Services vault.
examples:
  - name: Sets backup related properties of the Recovery Services vault. (autogenerated)
    text: az backup vault backup-properties set --backup-storage-redundancy GeoRedundant --name MyRecoveryServicesVault --resource-group MyResourceGroup --subscription MySubscription
    crafted: true
"""

helps['backup vault backup-properties show'] = """
type: command
short-summary: Gets backup related properties of the Recovery Services vault.
examples:
  - name: Gets backup related properties of the Recovery Services vault. (autogenerated)
    text: az backup vault backup-properties show --name MyRecoveryServicesVault --resource-group MyResourceGroup
    crafted: true
"""

helps['backup vault create'] = """
type: command
short-summary: Create a new Recovery Services vault.
examples:
  - name: Create a new Recovery Services vault. (autogenerated)
    text: az backup vault create --location westus2 --name MyRecoveryServicesVault --resource-group MyResourceGroup
    crafted: true
"""

helps['backup vault delete'] = """
type: command
short-summary: Delete an existing Recovery services vault.
examples:
  - name: Delete an existing Recovery services vault. (autogenerated)
    text: az backup vault delete --name MyRecoveryServicesVault --resource-group MyResourceGroup --yes
    crafted: true
"""

helps['backup vault list'] = """
type: command
short-summary: List Recovery service vaults within a subscription.
"""

helps['backup vault show'] = """
type: command
short-summary: Show details of a particular Recovery service vault.
examples:
  - name: Show details of a particular Recovery service vault. (autogenerated)
    text: az backup vault show --name MyRecoveryServicesVault --resource-group MyResourceGroup
    crafted: true
"""
