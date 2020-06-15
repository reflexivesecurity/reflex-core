""" SNSNotifier class """
import os

import boto3

from reflex_core.notifiers import Notifier


class SNSNotifier(Notifier):
    """ SNS (Simple Notification Service) Notifier """

    CLIENT = boto3.client("sns")

    def notify(self, subject, message):
        """Sends a notification message via SNS.

        Args:
            subject (str): The notification subject.
            message (str): The notification message.
        """
        sns_topic = self.get_sns_topic()

        self.CLIENT.publish(TopicArn=sns_topic, Subject=subject, Message=message)

    def get_sns_topic(self):
        """Get the SNS topic to send a notification to.

        Returns:
            str: The SNS topic ARN which we will send a message to.
        """
        return os.environ["SNS_TOPIC"]
