"""Convenience wrapper for running apility directly from source tree."""

import unittest
import xmlrunner

if __name__ == '__main__':
    with open('test-results.xml', 'wb') as output:
        unittest.main(
            module='tests.client_test',
            testRunner=xmlrunner.XMLTestRunner(output=output),
            failfast=False,
            buffer=False,
            catchbreak=False)
