""" SNSNotifier class """
import os

import boto3

from reflex_core.notifiers import Notifier


class SNSNotifier(Notifier):
    """ SNS (Simple Notification Service) Notifier """

    CLIENT = boto3.client("sns")

    def notify(self, message):
        """ Sends a notification message via SNS. """
        sns_topic = self.get_sns_topic()

        self.CLIENT.publish(TopicArn=sns_topic, Message=message)

    def get_sns_topic(self):
        """ Get the SNS topic to notify. """
        return os.environ["SNS_TOPIC"]
