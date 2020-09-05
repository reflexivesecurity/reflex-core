""" Module for the SubscriptionConfirmation class """
import logging
import os

import requests

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOGGER = logging.getLogger()
LOGGER.setLevel(LOG_LEVEL)


def is_subscription_confirmation(event):
    """Determines if  event payload is for confirming subscriptions."""
    return event.get("Type") == "SubscriptionConfirmation"


def confirm_subscription(event):
    """Respond to an outside subscription notification.

    For SNS topic subscriptions that require manual subscription confirmations, this
    function will parse the event message and make the request to the confirmation
    url.

    Returns:
        None
    """

    subscription_url = event.get("SubscribeURL")
    LOGGER.info("Confirming subscription by requesting URL: %s", subscription_url)
    requests.get(subscription_url)
