# project
from checks import AgentCheck
from tests.core.test_wmi import TestCommonWMI
from tests.checks.common import AgentCheckTest


class WindowsServiceTestCase(AgentCheckTest, TestCommonWMI):
    CHECK_NAME = 'windows_service'

    WIN_SERVICES_CONFIG = {
        'host': ".",
        'services': ["WinHttpAutoProxySvc", "WSService"]
    }

    def test_check(self):
        """
        Returns the right service checks
        """
        # Run check
        config = {
            'instances': [self.WIN_SERVICES_CONFIG]
        }

        self.run_check(config)

        # Test service checks
        self.assertServiceCheck('windows_service.state', status=AgentCheck.OK, count=1,
                                tags=[u'service:WinHttpAutoProxySvc',
                                      u'host:' + self.check.hostname])
        self.assertServiceCheck('windows_service.state', status=AgentCheck.CRITICAL, count=1,
                                tags=[u'service:WSService',
                                      u'host:' + self.check.hostname])

        self.coverage_report()
