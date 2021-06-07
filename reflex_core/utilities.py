""" Utility functions """

import logging
import os

import boto3

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOGGER = logging.getLogger()
LOGGER.setLevel(LOG_LEVEL)


def get_account_list():
    """ Get list of accounts for scanning """
    return [boto3.client("sts").get_caller_identity().get("Account")]


def get_region_list():
    """ Get list of regions for scanning """
    response = boto3.client("ec2").describe_regions()
    region_names = []

    for region in response["Regions"]:
        region_names.append(region["RegionName"])

    return region_names


def get_boto3_client(
    service, role_arn, session_name="ReflexSession", region="us-east-1"
):
    """Instantiate and return a boto3 client.

    Returns:
        boto3.client: A boto3 client for the service that triggered the event.

        The boto3 client will be for the specific account and region that triggered
        the event. If no service can be parsed from the event (usually as a result
        of the event being custom), or the parsed service name is invalid, this
        will return None.
    """
    if service is None:
        LOGGER.warning("No service name present. Boto3 client not created.")
        return None

    if service not in boto3.session.Session().get_available_services():
        LOGGER.warning("Service name invalid. Boto3 client not created.")
        return None

    sts_client = boto3.client("sts")
    sts_response = sts_client.assume_role(
        RoleArn=role_arn, RoleSessionName=session_name
    )
    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=sts_response["Credentials"]["AccessKeyId"],
        aws_secret_access_key=sts_response["Credentials"]["SecretAccessKey"],
        aws_session_token=sts_response["Credentials"]["SessionToken"],
    )


def get_boto3_resource(
    service, role_arn, session_name="ReflexSession", region="us-east-1"
):
    """Instantiate and return a boto3 resource.

    Returns:
        boto3.resource: A boto3 resource for the service that triggered the event.

        The boto3 resource will be for the specific account and region requested.
        If the service name is invalid, this will return None.
    """
    if service is None:
        LOGGER.warning("No service name present. Boto3 resource not created.")
        return None

    if service not in boto3.session.Session().get_available_services():
        LOGGER.warning("Service name invalid. Boto3 resource not created.")
        return None

    sts_client = boto3.client("sts")
    sts_response = sts_client.assume_role(
        RoleArn=role_arn, RoleSessionName=session_name
    )
    return boto3.resource(
        service,
        region_name=region,
        aws_access_key_id=sts_response["Credentials"]["AccessKeyId"],
        aws_secret_access_key=sts_response["Credentials"]["SecretAccessKey"],
        aws_session_token=sts_response["Credentials"]["SessionToken"],
    )


def get_scanning_role_arn(account):
    """Get and return the ARN of the role we will assume.

    Returns:
        str: The ARN of the IAM role we will assume for our boto3 client.
    """
    return f"arn:aws:iam::{account}:role/{os.environ.get('SCANNING_ROLE_NAME')}"

def get_assume_role_arn(account):
    """Get and return the ARN of the role we will assume.

    Returns:
        str: The ARN of the IAM role we will assume for our boto3 client.
    """
    return f"arn:aws:iam::{account}:role/{os.environ.get('ASSUME_ROLE_NAME')}"
