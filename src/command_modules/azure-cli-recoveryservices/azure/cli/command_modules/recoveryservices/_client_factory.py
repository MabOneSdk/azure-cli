def _recoveryservices_client_factory(**_):
    from azure.mgmt.recoveryservices import RecoveryServicesClient
    from azure.cli.core.commands.client_factory import get_mgmt_service_client

    return get_mgmt_service_client(RecoveryServicesClient)

def vaults_mgmt_client_factory(_):
    return _recoveryservices_client_factory().vaults