# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from collections import OrderedDict


def transform_container(result):
    return OrderedDict([('Name', result['properties']['friendlyName']),
                        ('Resource Group', result['resourceGroup']),
                        ('Type', result['properties']['backupManagementType']),
                        ('Registration Status', result['properties']['registrationStatus'])])


def transform_wl_container(result):
    columns = []
    columns.append(('Name', result['properties']['friendlyName']))
    columns.append(('Status', result['properties']['registrationStatus']))
    columns.append(('Container Type', result['properties']['containerType']))

    workloads = [workload['type'] for workload in result['properties']['extendedInfo']['inquiryInfo']['inquiryDetails']]

    workloads = ', '.join(workloads)
    columns.append(('WorkloadsPresent', workloads))

    columns.append(('Health Status', result['properties']['healthStatus']))

    return OrderedDict(columns)


def transform_item(result):
    columns = []
    columns.append(('Name', result['properties']['friendlyName']))
    columns.append(('Resource Group', result['resourceGroup']))
    columns.append(('Type', result['properties']['workloadType']))
    columns.append(('Last Backup Status', result['properties']['lastBackupStatus']))
    columns.append(('Last Recovery Point', result['properties']['lastRecoveryPoint']))
    columns.append(('Protection Status', result['properties']['protectionStatus']))
    columns.append(('Health Status', result['properties']['healthStatus']))

    if result['properties']['healthDetails'] is not None:
        recommendations = []
        for health_detail in result['properties']['healthDetails']:
            recommendations.append(', '.join(health_detail['recommendations']))
        columns.append(('Recommendations', ', '.join(recommendations)))

    return OrderedDict(columns)


def transform_wl_item(result):
    columns = []
    columns.append(('Name', result['properties']['friendlyName']))
    columns.append(('WorkloadType', result['properties']['workloadType']))
    columns.append(('ContainerUniqueName', result['properties']['serverName']))
    columns.append(('Protection Status', result['properties']['protectionStatus']))
    columns.append(('Latest Recovery Point', result['properties']['lastRecoveryPoint']))

    return OrderedDict(columns)


def transform_protectable_item(result):
    columns = []
    columns.append(('Name', result['properties']['friendlyName']))
    columns.append(('ProtectableItemType', result['properties']['protectableItemType']))
    columns.append(('ParentName', result['properties']['parentName']))
    columns.append(('ServerName', result['properties']['serverName']))
    columns.append(('isProtected', result['properties']['protectionState']))

    return OrderedDict(columns)


def transform_job(result):
    columns = []
    columns.append(('Name', result['name']))
    columns.append(('Operation', result['properties']['operation']))
    columns.append(('Status', result['properties']['status']))
    columns.append(('Item Name', result['properties']['entityFriendlyName']))
    columns.append(('Start Time UTC', result['properties']['startTime']))

    if result['properties']['backupManagementType'] == 'AzureIaasVM':
        columns.append(('Duration', result['properties']['duration']))
    elif result['properties']['backupManagementType'] == 'AzureStorage':
        columns.append(('Duration', result['properties']['additionalProperties']['duration']))

    return OrderedDict(columns)


def transform_wl_policy(result):
    return OrderedDict([('Name', result['name']),
                        ('Resource Group', result['resourceGroup']),
                        ('BackupManagementType', result['properties']['backupManagementType']),
                        ('WorkloadType', result['properties']['workLoadType'])])


def transform_wl_policy_s(result):
    columns = []
    columns.append(('Name', result['name']))
    columns.append(('WorkloadType', result['properties']['workLoadType']))

    sub_protection_policy = result['properties']['subProtectionPolicy']

    differential, log = [False] * 2

    for policy in sub_protection_policy:
        if policy['policyType'] == 'Full':
            backup_time = policy['schedulePolicy']['scheduleRunTimes'][0]
            frequency = policy['schedulePolicy']['scheduleRunFrequency']
        if policy['policyType'] == 'Log':
            log = True
        if policy['policyType'] == 'Differential':
            differential = True

    columns.append(('BackupTime', backup_time))
    columns.append(('Frequency', frequency))
    columns.append(('IsDifferentialBackupEnabled', 'Yes' if differential else 'No'))
    if result['properties']['workLoadType'] == 'SQLDataBase':
        columns.append(('IsLogBackupEnabled', 'Yes' if log else 'No'))

    return OrderedDict(columns)


def transform_policy(result):
    return OrderedDict([('Name', result['name']),
                        ('Resource Group', result['resourceGroup']),
                        ('Type', result['properties']['backupManagementType'])])


def transform_recovery_point(result):
    return OrderedDict([('Name', result['name']),
                        ('Time', result['properties']['recoveryPointTime']),
                        ('Consistency', result['properties']['recoveryPointType'])])


def transform_wl_recovery_point(result):
    return OrderedDict([('Name', result['name']),
                        ('Time', result['properties']['recoveryPointTimeInUtc']),
                        ('Consistency', result['properties']['type']),
                        ('BackupManagementType', "AzureWorkload"),
                        ('Item Name', result['id'].split('/')[14]),
                        ('RecoveryPointType', result['properties']['objectType'])])


def transform_container_list(container_list):
    return [transform_container(c) for c in container_list]


def transform_item_list(item_list):
    return [transform_item(i) for i in item_list]


def transform_protectable_item_list(protectable_item_list):
    return [transform_protectable_item(i) for i in protectable_item_list]


def transform_job_list(job_list):
    return [transform_job(j) for j in job_list]


def transform_policy_list(policy_list):
    return [transform_policy(p) for p in policy_list]


def transform_recovery_point_list(recovery_point_list):
    return [transform_recovery_point(rp) for rp in recovery_point_list]


def transform_wl_recovery_point_list(recovery_point_list):
    return [transform_wl_recovery_point(rp) for rp in recovery_point_list]


def transform_wl_container_list(container_list):
    return [transform_wl_container(c) for c in container_list]


def transform_wl_item_list(item_list):
    return [transform_wl_item(i) for i in item_list]


def transform_wl_policy_list(policy_list):
    return [transform_wl_policy(p) for p in policy_list]


def transform_wl_policy_show(policy_list):
    return [transform_wl_policy_s(p) for p in policy_list]