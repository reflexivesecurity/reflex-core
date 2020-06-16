""" Generic Notifier class """

class Notifier():
    """ The Notifier base class """

    def notify(self, subject, message):
        """Send a notification.

        Args:
            subject (str): The subject of the notification.
            message (str): The notification message.

        Raises:
            NotImplementedError: Raised if the Notifier has not implemented
                logic for sending a notification.
        """
        raise NotImplementedError("notify is not implemented.")
