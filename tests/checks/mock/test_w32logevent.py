# project
from tests.core.test_wmi import TestCommonWMI
from tests.checks.common import AgentCheckTest


class W32LogEventTestCase(AgentCheckTest, TestCommonWMI):
    CHECK_NAME = 'win32_event_log'

    WIN_LOGEVENT_CONFIG = {
        'host': ".",
        'tags': ["mytag1", "mytag2"],
        'sites': ["Default_Web_Site", "Failing site"],
        'logfile': ["Application"],
        'type': ["Error", "Warning"],
        'source_name': ["MSSQLSERVER"]
    }

    def test_check(self):
        """
        Returns the right metrics and service checks
        """
        # Run check
        config = {
            'instances': [self.WIN_LOGEVENT_CONFIG]
        }
        self.run_check_twice(config)

        self.assertEvent('SomeMessage', count=1,
                         tags=self.WIN_LOGEVENT_CONFIG['tags'],
                         msg_title='Application/MSQLSERVER',
                         event_type='win32_log_event', alert_type='error',
                         source_type_name='event viewer')

        self.coverage_report()
