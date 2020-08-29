""" Module for the SubscriptionConfirmation class """
import logging
import os
import requests


LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()


class SubscriptionConfirmation:
    """Class for managing subscription confirmations in Reflex

    Attributes:
        event (dict): The AWS subscription confirmation event that the lambda
        is responding to.
    """

    LOGGER = logging.getLogger()
    LOGGER.setLevel(LOG_LEVEL)

    def __init__(self, event):
        """Initialize the SubscriptionConfirmation object.

        Args:
            event (dict): An AWS CloudWatch event.
        """
        self.event = event

    def handle_subscription_confirmation(self):
        """Respond to an outside subscription notification.

        For SNS topic subscriptions that require manual subscription confirmations, this
        function will parse the event message and make the request to the confirmation
        url.

        Returns:
            None
        """

        subscription_url = self.event.get("SubscribeURL")
        requests.get(subscription_url)
