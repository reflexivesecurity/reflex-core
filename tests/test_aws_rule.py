import os
import unittest
from unittest.mock import patch

from reflex_core import aws_rule
from reflex_core.notifiers import Notifier


class TestAwsRule(unittest.TestCase):
    EVENT = {}

    def test_create_aws_rule_fully_implemented(self):
        FullyImplementedAwsRule(self.EVENT)

    def test_create_aws_rule_all_function_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            NotImplementedAwsRule(self.EVENT)

    def test_extract_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            ExtractNotImplementedAwsRule(self.EVENT)

    def test_remediate_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            test = RemediateNotImplementedAwsRule(self.EVENT)
            test.remediate()

    def test_resource_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            test = ResourceNotImplementedAwsRule(self.EVENT)
            test.resource_compliant()

    def test_message_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            test = MessageNotImplementedAwsRule(self.EVENT)
            test.get_remediation_message()

    def test_fully_implemented_run_compliance_rule(self):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)
            test.run_compliance_rule()
            boto.assert_called_with('Publish',
                                    {'TopicArn': 'test', 'Message': None})

    def test_add_and_execute_pre_remediation_action(self):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            def print_test():
                print("test")

            test.add_pre_remediation_functions(print_test)
            test.run_compliance_rule()
            self.assertEqual(test.pre_remediation_functions[0], print_test)
            boto.assert_called_with('Publish',
                                    {'TopicArn': 'test', 'Message': None})

    def test_add_and_execute_pre_remediation_actions(self):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            def print_test():
                print("test")

            test.add_pre_remediation_functions([print_test, print_test])
            test.run_compliance_rule()
            self.assertEqual(test.pre_remediation_functions,
                             [print_test, print_test])

            boto.assert_called_with('Publish',
                                    {'TopicArn': 'test', 'Message': None})

    @patch('logging.Logger.warning')
    def test_add_and_execute_non_executable_pre_remediation_action(self,
                                                                   mock_log):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            my_string = "string"

            test.add_pre_remediation_functions(my_string)
            test.run_compliance_rule()
            mock_log.assert_called_with(
                '%s is not a function or list. Not adding to list of pre-remediation functions.',
                'string')

    @patch('logging.Logger.warning')
    def test_add_and_execute_non_executables_pre_remediation_actions(self,
                                                                     mock_log):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            my_string = "string"

            test.add_pre_remediation_functions([my_string, my_string])
            test.run_compliance_rule()
            mock_log.assert_called_with(
                '%s is not a function. Not adding to list of pre-remediation functions.',
                'string')

    def test_remove_pre_remediation_action(self):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            def print_test():
                print("test")

            test.add_pre_remediation_functions(print_test)
            test.remove_pre_remediation_functions(print_test)
            test.run_compliance_rule()
            self.assertEqual(test.pre_remediation_functions, [])

            boto.assert_called_with('Publish',
                                    {'TopicArn': 'test', 'Message': None})

    def test_remove_pre_remediation_actions(self):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            def print_test():
                print("test")

            test.add_pre_remediation_functions([print_test, print_test])
            test.remove_pre_remediation_functions([print_test, print_test])
            test.run_compliance_rule()
            self.assertEqual(test.pre_remediation_functions, [])

            boto.assert_called_with('Publish',
                                    {'TopicArn': 'test', 'Message': None})

    @patch('logging.Logger.warning')
    def test_remove_pre_remediation_actions_value_error(self, mock_log):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            def print_test():
                print("test")

            def new_test():
                print("test")

            test.add_pre_remediation_functions([print_test, print_test])
            test.remove_pre_remediation_functions([print_test, new_test])
            test.run_compliance_rule()
            self.assertEqual(test.pre_remediation_functions, [print_test])

            boto.assert_called_with('Publish',
                                    {'TopicArn': 'test', 'Message': None})
            self.assertEqual(mock_log.call_args[0][0],
                             '%s is not in the list of pre-remediation functions. Skipping')

    @patch('logging.Logger.warning')
    def test_remove_pre_remediation_action_value_error(self, mock_log):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            def print_test():
                print("test")

            def new_test():
                print("test")

            test.add_pre_remediation_functions(print_test)
            test.remove_pre_remediation_functions(new_test)
            test.run_compliance_rule()
            self.assertEqual(test.pre_remediation_functions, [print_test])

            boto.assert_called_with('Publish',
                                    {'TopicArn': 'test', 'Message': None})
            self.assertEqual(mock_log.call_args[0][0],
                             '%s is not in the list of pre-remediation functions. Skipping')

    def test_add_and_execute_post_remediation_action(self):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            def print_test():
                print("test")

            test.add_post_remediation_functions(print_test)
            test.run_compliance_rule()
            self.assertEqual(test.post_remediation_functions[1], print_test)
            boto.assert_called_with('Publish',
                                    {'TopicArn': 'test', 'Message': None})

    def test_add_and_execute_post_remediation_actions(self):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            def print_test():
                print("test")

            test.add_post_remediation_functions([print_test, print_test])
            test.run_compliance_rule()
            self.assertEqual(test.post_remediation_functions[1:3],
                             [print_test, print_test])

            boto.assert_called_with('Publish',
                                    {'TopicArn': 'test', 'Message': None})

    @patch('logging.Logger.warning')
    def test_add_and_execute_non_executable_post_remediation_action(self,
                                                                    mock_log):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            my_string = "string"

            test.add_post_remediation_functions(my_string)
            test.run_compliance_rule()
            mock_log.assert_called_with(
                '%s is not a function or list. Not adding to list of post-remediation functions.',
                'string')

    @patch('logging.Logger.warning')
    def test_add_and_execute_non_executable_post_remediation_actions(self,
                                                                     mock_log):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            my_string = "string"

            test.add_post_remediation_functions([my_string, my_string])
            test.run_compliance_rule()
            mock_log.assert_called_with(
                '%s is not a function. Not adding to list of post-remediation functions.',
                'string')

    def test_remove_post_remediation_action(self):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            def print_test():
                print("test")

            test.add_post_remediation_functions(print_test)
            test.remove_post_remediation_functions(print_test)
            test.run_compliance_rule()
            self.assertEqual(len(test.post_remediation_functions), 1)

            boto.assert_called_with('Publish',
                                    {'TopicArn': 'test', 'Message': None})

    def test_remove_post_remediation_actions(self):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            def print_test():
                print("test")

            test.add_post_remediation_functions([print_test, print_test])
            test.remove_post_remediation_functions([print_test, print_test])
            test.run_compliance_rule()
            self.assertEqual(len(test.post_remediation_functions), 1)

            boto.assert_called_with('Publish',
                                    {'TopicArn': 'test', 'Message': None})

    @patch('logging.Logger.warning')
    def test_remove_post_remediation_actions_value_error(self, mock_log):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            def print_test():
                print("test")

            def new_test():
                print("test")

            test.add_post_remediation_functions([print_test, print_test])
            test.remove_post_remediation_functions([print_test, new_test])
            test.run_compliance_rule()
            self.assertEqual(test.post_remediation_functions[1], print_test)

            boto.assert_called_with('Publish',
                                    {'TopicArn': 'test', 'Message': None})
            self.assertEqual(mock_log.call_args[0][0],
                             '%s is not in the list of post-remediation functions. Skipping')

    @patch('logging.Logger.warning')
    def test_remove_post_remediation_action_value_error(self, mock_log):
        os.environ["SNS_TOPIC"] = "test"
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)

            def print_test():
                print("test")

            def new_test():
                print("test")

            test.add_post_remediation_functions(print_test)
            test.remove_post_remediation_functions(new_test)
            test.run_compliance_rule()
            self.assertEqual(test.post_remediation_functions[1], print_test)

            boto.assert_called_with('Publish',
                                    {'TopicArn': 'test', 'Message': None})
            self.assertEqual(mock_log.call_args[0][0],
                             '%s is not in the list of post-remediation functions. Skipping')

    def test_add_notifier(self):
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)
            test.add_notifiers(FakeNotifier)
            self.assertEqual(test.notifiers[1], FakeNotifier)

    def test_add_notifiers(self):
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)
            test.add_notifiers([FakeNotifier, FakeNotifier])
            self.assertEqual(test.notifiers[1:3], [FakeNotifier, FakeNotifier])

    @patch('logging.Logger.warning')
    def test_add_notifier_failure_not_class(self, mock_log):
        with self.assertRaises(TypeError):
            test = FullyImplementedAwsRule(self.EVENT)
            test.add_notifiers('FakeNotifier')

    @patch('logging.Logger.warning')
    def test_add_notifiers_failure_not_class(self, mock_log):
        with self.assertRaises(TypeError):
            test = FullyImplementedAwsRule(self.EVENT)
            test.add_notifiers(['FakeNotifier', 'FakeNotifier'])

    @patch('logging.Logger.warning')
    def test_add_notifier_failure_wrong_class(self, mock_log):
        test = FullyImplementedAwsRule(self.EVENT)
        test.add_notifiers(NotANotifier)
        self.assertEqual(mock_log.call_args[0][0], '%s is not a Notifier or list. Not adding to list of Notifiers.')

    @patch('logging.Logger.warning')
    def test_add_notifiers_failure_wrong_class(self, mock_log):
        test = FullyImplementedAwsRule(self.EVENT)
        test.add_notifiers([NotANotifier, NotANotifier])
        self.assertEqual(mock_log.call_args[0][0], '%s is not a Notifier. Not adding to list of Notifiers.')

    def test_remove_notifier(self):
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)
            test.add_notifiers(FakeNotifier)
            test.remove_notifiers(FakeNotifier)
            self.assertEqual(len(test.notifiers), 1)

    def test_remove_notifiers(self):
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            test = FullyImplementedAwsRule(self.EVENT)
            test.add_notifiers([FakeNotifier, FakeNotifier])
            test.remove_notifiers([FakeNotifier, FakeNotifier])
            self.assertEqual(len(test.notifiers), 1)

    @patch('logging.Logger.warning')
    def test_remove_notifier_failure_not_class(self, mock_log):
        test = FullyImplementedAwsRule(self.EVENT)
        test.add_notifiers(FakeNotifier)
        test.remove_notifiers('FakeNotifier')
        self.assertEqual(mock_log.call_args[0][0],
                         '%s is not in the list of Notifiers. Skipping')

    @patch('logging.Logger.warning')
    def test_remove_notifiers_failure_not_class(self, mock_log):
        test = FullyImplementedAwsRule(self.EVENT)
        test.add_notifiers([FakeNotifier, FakeNotifier])
        test.remove_notifiers(['FakeNotifier', 'FakeNotifier'])
        self.assertEqual(mock_log.call_args[0][0],
                         '%s is not in the list of Notifiers. Skipping')

    def test_notify(self):
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            os.environ["SNS_TOPIC"] = "test"
            test = FullyImplementedAwsRule(self.EVENT)
            test.notify()
            boto.assert_called_with('Publish', {'TopicArn': 'test', 'Message': None})

    @patch('logging.Logger.error')
    def test_notify_exception(self, mock_log):
        with patch('botocore.client.BaseClient._make_api_call') as boto:
            os.environ["SNS_TOPIC"] = "test"
            test = FullyImplementedAwsRule(self.EVENT)
            test.add_notifiers(FakeNotifier)
            test.notify()
            boto.assert_called_with('Publish', {'TopicArn': 'test', 'Message': None})
            self.assertEqual(mock_log.call_args[0][0],
                             'An error occurred while trying to send a notification: %s')




class NotImplementedAwsRule(aws_rule.AWSRule):
    def __init__(self, event):
        super().__init__(event)


class FullyImplementedAwsRule(aws_rule.AWSRule):
    def __init__(self, event):
        super().__init__(event)

    def remediate(self):
        pass

    def extract_event_data(self, event):
        pass

    def resource_compliant(self):
        pass

    def get_remediation_message(self):
        pass


class ExtractNotImplementedAwsRule(aws_rule.AWSRule):
    def __init__(self, event):
        super().__init__(event)

    def remediate(self):
        pass

    def resource_compliant(self):
        pass

    def get_remediation_message(self):
        pass


class RemediateNotImplementedAwsRule(aws_rule.AWSRule):
    def __init__(self, event):
        super().__init__(event)

    def extract_event_data(self, event):
        pass

    def resource_compliant(self):
        pass

    def get_remediation_message(self):
        pass


class ResourceNotImplementedAwsRule(aws_rule.AWSRule):
    def __init__(self, event):
        super().__init__(event)

    def remediate(self):
        pass

    def extract_event_data(self, event):
        pass

    def get_remediation_message(self):
        pass


class MessageNotImplementedAwsRule(aws_rule.AWSRule):
    def __init__(self, event):
        super().__init__(event)

    def remediate(self):
        pass

    def extract_event_data(self, event):
        pass

    def resource_compliant(self):
        pass


class FakeNotifier(Notifier):
    def notify(self, message):
        raise ValueError


class NotANotifier:
    def notify(self):
        pass
