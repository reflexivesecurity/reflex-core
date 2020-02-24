""" Module for the AWSRule class """
import logging

from reflex_core.notifiers import Notifier
from reflex_core.notifiers import SNSNotifier


class AWSRule:
    """ Generic class for AWS compliance rules """

    LOGGER = logging.getLogger(__name__)

    def __init__(self, event):
        """ Initialize the rule object """
        self.extract_event_data(event)
        self.pre_remediation_functions = []
        self.post_remediation_functions = []
        self.notifiers = []

        self.add_post_remediation_functions(self.notify)
        self.add_notifiers(SNSNotifier)

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
            if not self.resource_compliant():
                self.pre_remediation()
                self.remediate()
                self.post_remediation()
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
        for pre_remediation_function in self.pre_remediation_functions:
            pre_remediation_function()

    def post_remediation(self):
        """ Any steps to take after remediating the resource """
        for post_remediation_function in self.post_remediation_functions:
            post_remediation_function()

    def get_remediation_message(self):
        """ Provides a message about the remediation to be sent in notifications """
        raise NotImplementedError("get_remediation_message not implemented")

    def add_pre_remediation_functions(self, functions):
        """
        Sets a function or list of functions to be run before remediation action occurs.

        If anything other than a function is present in the list, it will be ignored.
        If something other than a function or list is passed, it will be ignored.
        """
        if isinstance(functions, list):
            for function in functions:
                if callable(function):
                    self.pre_remediation_functions.append(function)
                else:
                    self.LOGGER.warning(
                        "%s is not a function. Not adding to list of pre-remediation functions.",
                        function,
                    )
        elif callable(functions):
            self.pre_remediation_functions.append(functions)
        else:
            self.LOGGER.warning(
                "%s is not a function or list. Not adding to list of pre-remediation functions.",
                functions,
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
                    self.pre_remediation_functions.remove(function)
                except ValueError:
                    self.LOGGER.warning(
                        "%s is not in the list of pre-remediation functions. Skipping",
                        function,
                    )
        else:
            try:
                self.pre_remediation_functions.remove(functions)
            except ValueError:
                self.LOGGER.warning(
                    "%s is not in the list of pre-remediation functions. Skipping",
                    functions,
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
                    self.post_remediation_functions.append(function)
                else:
                    self.LOGGER.warning(
                        "%s is not a function. Not adding to list of post-remediation functions.",
                        function,
                    )
        elif callable(functions):
            self.post_remediation_functions.append(functions)
        else:
            self.LOGGER.warning(
                "%s is not a function or list. Not adding to list of post-remediation functions.",
                functions,
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
                    self.post_remediation_functions.remove(function)
                except ValueError:
                    self.LOGGER.warning(
                        "%s is not in the list of post-remediation functions. Skipping",
                        function,
                    )
        else:
            try:
                self.post_remediation_functions.remove(functions)
            except ValueError:
                self.LOGGER.warning(
                    "%s is not in the list of post-remediation functions. Skipping",
                    functions,
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
                    self.notifiers.append(notifier)
                else:
                    self.LOGGER.warning(
                        "%s is not a Notifier. Not adding to list of Notifiers.",
                        notifier,
                    )
        elif issubclass(notifiers, Notifier):
            self.notifiers.append(notifiers)
        else:
            self.LOGGER.warning(
                "%s is not a Notifier or list. Not adding to list of Notifiers.",
                notifiers,
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
                    self.notifiers.remove(notifier)
                except ValueError:
                    self.LOGGER.warning(
                        "%s is not in the list of Notifiers. Skipping", notifier
                    )
        else:
            try:
                self.notifiers.remove(notifiers)
            except ValueError:
                self.LOGGER.warning(
                    "%s is not in the list of Notifiers. Skipping", notifiers
                )

    def notify(self):
        """ Send notification messages with all Notifiers """
        for notifier in self.notifiers:
            try:
                notifier().notify(self.get_remediation_message())
            except Exception as exp:  #  pylint: disable=broad-except
                self.LOGGER.error(
                    "An error occurred while trying to send a notification: %s", exp
                )
