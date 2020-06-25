Notifiers
=========

.. module:: reflex_core.notifiers

Notifiers send notifications when a Rule detects a misconfigured resource. The Notifier class provides
a basic interface for sending notifications, and the SNSNotifier is a concrete implementation for
sending notifications with AWS's SNS service.

Notifier
--------

.. autoclass:: Notifier
   :members:

SNSNotifier
-----------

.. autoclass:: SNSNotifier
    :members:
