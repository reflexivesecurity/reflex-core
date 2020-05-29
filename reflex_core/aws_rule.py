""" Module for the AWSRule class """
import logging
import os
import re

import boto3

from reflex_core.notifiers import Notifier
from reflex_core.notifiers import SNSNotifier


LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()


class AWSRule:
    """Generic class for AWS compliance rules.

    Attributes:
        event (dict): The AWS CloudWatch event that the rule is responding to.
        account (str): The AWS account number that the event occurred in.
        region (str): The AWS region that the event occurred in.
        service (str): The name of the AWS service that triggered the event.
        client ()
    """

    LOGGER = logging.getLogger()
    LOGGER.setLevel(LOG_LEVEL)

    def __init__(self, event):
        """Initialize the rule object.

        Args:
            event (dict): An AWS CloudWatch event.
        """
        self.LOGGER.info("Incoming event: %s", event)
        self.event = event
        self.account = event["account"]
        self.region = event["region"]
        self.service = self.parse_service_name(event["source"])
        self.client = self.get_boto3_client()

        self.extract_event_data(event)
        self.pre_remediation_functions = []
        self.post_remediation_functions = []
        self.notifiers = []

        self.add_notifiers(SNSNotifier)

    def get_boto3_client(self):
        """Instantiate and return a boto3 client.

        Returns:
            boto3.client: A boto3 client for the service that triggered the event.

            The boto3 client will be for the specific account and region that triggered
            the event. If no service can be parsed from the event (usually as a result
            of the event being custom), or the parsed service name is invalid, this
            will return None.
        """
        if self.service is None:
            self.LOGGER.warning("No service name present. Boto3 client not created.")
            return None

        if self.service not in boto3.session.Session().get_available_services():
            self.LOGGER.warning("Service name invalid. Boto3 client not created.")
            return None

        role_arn = self.get_role_arn()
        role_session_name = self.get_role_session_name()
        sts_client = boto3.client("sts")
        sts_response = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName=role_session_name
        )
        return boto3.client(
            self.service,
            region_name=self.region,
            aws_access_key_id=sts_response["Credentials"]["AccessKeyId"],
            aws_secret_access_key=sts_response["Credentials"]["SecretAccessKey"],
            aws_session_token=sts_response["Credentials"]["SessionToken"],
        )

    def get_role_arn(self):
        """ Get and return the ARN of the role we will assume """
        return f"arn:aws:iam::{self.account}:role/{os.environ.get('ASSUME_ROLE_NAME')}"

    def get_role_session_name(self):
        """ Get and return the AWS role session name """
        return f"{self.__class__.__name__}Session"

    def parse_service_name(self, event_source):
        """ Parse the AWS service name from event["source"] """
        if not event_source.startswith("aws."):
            self.LOGGER.info(
                "Non-AWS event source present. This is a custom CloudWatch Event."
            )
            return None
        service_name = event_source.replace("aws.", "", 1)
        return service_name

    def extract_event_data(self, event):
        """ Extracts data from the event """
        raise NotImplementedError("extract_event_data not implemented")

    def run_compliance_rule(self):
        """
        Runs all steps of the compliance rule

        Checks for SystemExit to allow for use of sys.exit() to end rule
        execution without the Lambda failing, incrementing failure counter,
        and retrying.
        """
        try:
            self.LOGGER.debug("Checking if resource is compliant")
            if not self.resource_compliant():
                self.LOGGER.debug("Resource is not compliant")

                if self.should_remediate():
                    self.pre_remediation()

                    self.LOGGER.debug("Remediating resource")
                    self.remediate()
                    self.LOGGER.debug("Remediation complete")

                    self.post_remediation()

                self.notify()

                return

            self.LOGGER.debug("Resource is compliant")
        except SystemExit as exception:
            if exception.code is None or exception.code == 0:
                return
            raise

    def resource_compliant(self):
        """ Returns True if the resource is compliant, False otherwise """
        raise NotImplementedError("resource_compliant not implemented")

    def remediate(self):
        """ Fixes the configuration of the non-compliant resource """
        raise NotImplementedError("remediate not implemented")

    def pre_remediation(self):
        """ Any steps to take before remediating the resource """
        self.LOGGER.debug("Running pre-remediation functions")
        for pre_remediation_function in self.pre_remediation_functions:
            self.LOGGER.debug(
                "Running pre-remediation function %s", pre_remediation_function.__name__
            )
            pre_remediation_function()

    def post_remediation(self):
        """ Any steps to take after remediating the resource """
        self.LOGGER.debug("Running post-remediation functions")
        for post_remediation_function in self.post_remediation_functions:
            self.LOGGER.debug(
                "Running post-remediation function %s",
                post_remediation_function.__name__,
            )
            post_remediation_function()

    def _get_remediation_message(self):
        """
        Adds information that is relevant to all rules to the rule specific
        remediation message.
        """
        rule_message = self.get_remediation_message()

        message = (
            f"{rule_message}\n\n"
            f"Event time: {self.event['time']}\n"
            f"Raw event: {self.event}"
        )

        return message

    def get_remediation_message(self):
        """ Provides a message about the remediation to be sent in notifications """
        raise NotImplementedError("get_remediation_message not implemented")

    def get_remediation_message_subject(self):
        """
        Returns the subject to use when sending notifications

        Note: Subjects must be ASCII text that begin with a letter, number, or
        punctuation mark; must not include line breaks or control characters;
        and must be less than 100 characters long in order to be compatible
        with SNS. See https://docs.aws.amazon.com/sns/latest/api/API_Publish.html
        """
        subject = self.__class__.__name__
        subject_split = re.split(
            "(?=(?<=[a-z])[A-Z])|(?=[A-Z](?=[a-z])|(?=^[A-Z]))", subject
        )
        fixed_subject = " ".join(subject_split)
        return f"The Reflex {fixed_subject} was triggered."

    def add_pre_remediation_functions(self, functions):
        """
        Sets a function or list of functions to be run before remediation action occurs.

        If anything other than a function is present in the list, it will be ignored.
        If something other than a function or list is passed, it will be ignored.
        """
        if isinstance(functions, list):
            for function in functions:
                if callable(function):
                    self.LOGGER.debug(
                        "Adding %s to pre-remediation functions", function.__name__
                    )
                    self.pre_remediation_functions.append(function)
                else:
                    self.LOGGER.warning(
                        "%s is not a function. Not adding to list of pre-remediation functions.",
                        function.__name__,
                    )
        elif callable(functions):
            self.LOGGER.debug(
                "Adding %s to pre-remediation functions", functions.__name__
            )
            self.pre_remediation_functions.append(functions)
        else:
            self.LOGGER.warning(
                "%s is not a function or list. Not adding to list of pre-remediation functions.",
                functions.__name__,
            )

    def remove_pre_remediation_functions(self, functions):
        """
        Stop a function or list of functions from being run pre-remediation.

        Takes a function or list of functions and removes them from the list
        of pre-remediation functions. Anything not in the list will be ignored.
        """
        if isinstance(functions, list):
            for function in functions:
                try:
                    self.LOGGER.debug(
                        "Removing %s from pre-remediation functions", function.__name__
                    )
                    self.pre_remediation_functions.remove(function)
                except ValueError:
                    self.LOGGER.warning(
                        "%s is not in the list of pre-remediation functions. Skipping",
                        function.__name__,
                    )
        else:
            try:
                self.LOGGER.debug(
                    "Removing %s from pre-remediation functions", functions.__name__
                )
                self.pre_remediation_functions.remove(functions)
            except ValueError:
                self.LOGGER.warning(
                    "%s is not in the list of pre-remediation functions. Skipping",
                    functions.__name__,
                )

    def add_post_remediation_functions(self, functions):
        """
        Sets a function or list of functions to be run after remediation action occurs.

        If anything other than a function is present in the list, it will be ignored.
        If something other than a function or list is passed, it will be ignored.
        """
        if isinstance(functions, list):
            for function in functions:
                if callable(function):
                    self.LOGGER.debug(
                        "Adding %s to post-remediation functions", function.__name__
                    )
                    self.post_remediation_functions.append(function)
                else:
                    self.LOGGER.warning(
                        "%s is not a function. Not adding to list of post-remediation functions.",
                        function.__name__,
                    )
        elif callable(functions):
            self.LOGGER.debug(
                "Adding %s to post-remediation functions", functions.__name__
            )
            self.post_remediation_functions.append(functions)
        else:
            self.LOGGER.warning(
                "%s is not a function or list. Not adding to list of post-remediation functions.",
                functions.__name__,
            )

    def remove_post_remediation_functions(self, functions):
        """
        Stop a function or list of functions from being run post-remediation.

        Takes a function or list of functions and removes them from the list
        of post-remediation functions. Anything not in the list will be ignored.
        """
        if isinstance(functions, list):
            for function in functions:
                try:
                    self.LOGGER.debug(
                        "Removing %s from post-remediation functions", function.__name__
                    )
                    self.post_remediation_functions.remove(function)
                except ValueError:
                    self.LOGGER.warning(
                        "%s is not in the list of post-remediation functions. Skipping",
                        function.__name__,
                    )
        else:
            try:
                self.LOGGER.debug(
                    "Removing %s from post-remediation functions", functions.__name__
                )
                self.post_remediation_functions.remove(functions)
            except ValueError:
                self.LOGGER.warning(
                    "%s is not in the list of post-remediation functions. Skipping",
                    functions.__name__,
                )

    def add_notifiers(self, notifiers):
        """
        Sets a Notifier or list of Notifiers to send remediation notifications with.

        If anything other than a Notifier is present in the list, it will be ignored.
        If something other than a Notifier or list is passed, it will be ignored.
        """
        if isinstance(notifiers, list):
            for notifier in notifiers:
                if issubclass(notifier, Notifier):
                    self.LOGGER.debug(
                        "Adding %s to list of Notifiers", notifier.__name__
                    )
                    self.notifiers.append(notifier)
                else:
                    self.LOGGER.warning(
                        "%s is not a Notifier. Not adding to list of Notifiers.",
                        notifier.__name__,
                    )
        elif issubclass(notifiers, Notifier):
            self.LOGGER.debug("Adding %s to list of Notifiers", notifiers.__name__)
            self.notifiers.append(notifiers)
        else:
            self.LOGGER.warning(
                "%s is not a Notifier or list. Not adding to list of Notifiers.",
                notifiers.__name__,
            )

    def remove_notifiers(self, notifiers):
        """
        Stop a Notifier or list of Notifiers from sending remediation notifications.

        Takes a Notifier or list of Notifiers and stops them from sending
        remediation notifications. Anything not currently configured to send
        notifictions will be ignored.
        """
        if isinstance(notifiers, list):
            for notifier in notifiers:
                try:
                    self.LOGGER.debug(
                        "Removing %s from list of Notifiers", notifier.__name__
                    )
                    self.notifiers.remove(notifier)
                except ValueError:
                    self.LOGGER.warning(
                        "%s is not in the list of Notifiers. Skipping",
                        notifier.__name__,
                    )
        else:
            try:
                self.LOGGER.debug(
                    "Removing %s from list of Notifiers", notifiers.__name__
                )
                self.notifiers.remove(notifiers)
            except ValueError:
                self.LOGGER.warning(
                    "%s is not in the list of Notifiers. Skipping", notifiers.__name__
                )

    def notify(self):
        """ Send notification messages with all Notifiers """
        for notifier in self.notifiers:
            try:
                notifier().notify(
                    subject=self.get_remediation_message_subject(),
                    message=self._get_remediation_message(),
                )
            except Exception as exp:  #  pylint: disable=broad-except
                self.LOGGER.error(
                    "An error occurred while trying to send a notification: %s", exp
                )

    def should_remediate(self):
        """ Determines if remediation action should be taken. """
        mode = os.environ.get("MODE", "detect").lower()
        return mode == "remediate"
