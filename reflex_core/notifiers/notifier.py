""" Generic Notifier class """

class Notifier():
    """ The Notifier base class """

    def notify(self, subject, message):
        """ Send a notification """
        NotImplementedError("notify is not implemented.")
