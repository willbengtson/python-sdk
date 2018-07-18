import unittest
import requests
import time
import os

import apilityio.client as client
import apilityio.common as common

TEST_WRONG_KEY_SAMPLE = '123dcfe6-63d3-3cd2-b427-75d1b1c117ed'

TEST_KEY_SAMPLE = os.environ['APILITYIO_API_KEY']


class ClientTestCase(unittest.TestCase):

    def setUp(self):
        # This is a test
        x = 1

    def tearDown(self):
        #This is anothertest
        x = 2

    def test_upper(self):
        self.assertEqual('foo'.upper(), 'FOO')

    def testConnectionWithoutParameters(self):
        connection = client.Client()
        api_key_test, protocol_test, host_test = connection.GetConnectionData()
        self.assertEqual(api_key_test, None)
        self.assertEqual(protocol_test, common.HTTPS_PROTOCOL)
        self.assertEqual(host_test, common.DEFAULT_HOST)

    def testConnectionWithAPIKEYParameters(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        connection = client.Client(api_key=api_key_sample)
        api_key_test, protocol_test, host_test = connection.GetConnectionData()
        self.assertEqual(api_key_test, api_key_sample)
        self.assertEqual(protocol_test, common.HTTPS_PROTOCOL)
        self.assertEqual(host_test, common.DEFAULT_HOST)

    def testConnectionWithCustomProtocolParameters(self):
        connection = client.Client(protocol=common.HTTPS_PROTOCOL)
        api_key_test, protocol_test, host_test = connection.GetConnectionData()
        self.assertEqual(api_key_test, None)
        self.assertEqual(protocol_test, common.HTTPS_PROTOCOL)
        self.assertEqual(host_test, common.DEFAULT_HOST)

        connection = client.Client(protocol=common.HTTP_PROTOCOL)
        api_key_test, protocol_test, host_test = connection.GetConnectionData()
        self.assertEqual(api_key_test, None)
        self.assertEqual(protocol_test, common.HTTP_PROTOCOL)
        self.assertEqual(host_test, common.DEFAULT_HOST)

    def testConnectionWithCustomBadProtocolParameters(self):
        protocol_sample = 'TCP'
        try:
            connection = client.Client(protocol=protocol_sample)
            api_key_test, protocol_test, host_test = connection.GetConnectionData()
            self.assertEqual(protocol_sample, common.HTTPS_PROTOCOL)
        except:
            self.assertNotEqual(protocol_sample, common.HTTPS_PROTOCOL)

    def testConnectionWithCustomHostParameters(self):
        host_sample = 'google.com'
        connection = client.Client(host = host_sample)
        api_key_test, protocol_test, host_test = connection.GetConnectionData()
        self.assertEqual(api_key_test, None)
        self.assertEqual(protocol_test, common.HTTPS_PROTOCOL)
        self.assertEqual(host_test, host_sample)

    def testCheckGoodIPAddressConnectionAnonymous(self):
        ip_sample = '8.8.8.8'
        connection = client.Client()
        dto = connection.CheckIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.not_found)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.blacklists, [])

    def testCheckBadIPAddressConnectionAnonymous(self):
        ip_sample = '1.2.3.4'
        connection = client.Client()
        dto = connection.CheckIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.blacklists, [])

    def testCheckBadIPAddressConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '1.2.3.4'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.blacklists, [])

    def testCheckBadIPAddressConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        ip_sample = '1.2.3.4'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testCheckGoodBatchIPAddressesConnectionAnonymous(self):
        ip_sample = ['8.8.8.8','9.9.9.9','8.8.4.4']
        connection = client.Client()
        dto = connection.CheckBatchIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.ipblacklists_set, None)

    def testCheckBadBatchIPAddressesConnectionAnonymous(self):
        ip_sample = ['1.2.3.4', '114.223.63.139', '114.224.29.97']
        connection = client.Client()
        dto = connection.CheckBatchIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.ipblacklists_set, None)

    def testCheckBadBatchIPAddressesWrongFormatConnectionAnonymous(self):
        ip_sample = ['1.2.3.4', 'abcdef', 'mdmdmdmdm']
        connection = client.Client()
        try:
            dto = connection.CheckBatchIP(ip_sample)
            self.assertEqual(1,0,'Wrong formated values should return an error.')
        except:
            self.assertEqual(1,1,'Wrong formatted values interrupted execution.')

    def testCheckBadBatchIPAddressConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = ['1.2.3.4', '114.223.63.139', '114.224.29.97']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.ipblacklists_set, None)

    def testCheckBadBatchIPAddressConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        ip_sample = ['1.2.3.4', '114.223.63.139', '114.224.29.97']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testGeoIPAddressConnectionAnonymous(self):
        ip_sample = '8.8.8.8'
        connection = client.Client()
        dto = connection.GetGeoIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.geoip.address, '8.8.8.8')
        self.assertEqual(dto.geoip.asystem.asn, '15169')

    def testGeoPrivateIPAddressConnectionAnonymous(self):
        ip_sample = '10.0.0.1'
        connection = client.Client()
        dto = connection.GetGeoIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.geoip, None)

    def testGeoIPAddressConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '8.8.8.8'
        connection = client.Client(api_key = api_key_sample)
        dto = connection.GetGeoIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.geoip.address, '8.8.8.8')
        self.assertEqual(dto.geoip.asystem.asn, '15169')

    def testGeoIPAddressConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        ip_sample = '8.8.8.8'
        connection = client.Client(api_key = api_key_sample)
        dto = connection.GetGeoIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testGeoBatchIPAddressesConnectionAnonymous(self):
        ip_sample = ['8.8.8.8','9.9.9.9','8.8.4.4']
        connection = client.Client()
        dto = connection.GetGeoBatchIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.geolocated_ip_list[0].geoip.address, dto.geolocated_ip_list[0].ip_address)
        self.assertEqual(dto.geolocated_ip_list[1].geoip.address, dto.geolocated_ip_list[1].ip_address)
        self.assertEqual(dto.geolocated_ip_list[2].geoip.address, dto.geolocated_ip_list[2].ip_address)

    def testGeoBatchIPAddressesConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = ['8.8.8.8','9.9.9.9','8.8.4.4']
        connection = client.Client(api_key = api_key_sample)
        dto = connection.GetGeoBatchIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.geolocated_ip_list[0].geoip.address, dto.geolocated_ip_list[0].ip_address)
        self.assertEqual(dto.geolocated_ip_list[1].geoip.address, dto.geolocated_ip_list[1].ip_address)
        self.assertEqual(dto.geolocated_ip_list[2].geoip.address, dto.geolocated_ip_list[2].ip_address)

    def testGeoBatchIPAddressesConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        ip_sample = ['8.8.8.8','9.9.9.9','8.8.4.4']
        connection = client.Client(api_key = api_key_sample)
        dto = connection.GetGeoBatchIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testCheckGoodDomainConnectionAnonymous(self):
        domain_sample = 'google.com'
        connection = client.Client()
        dto = connection.CheckDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.response.score, 0)
        self.assertEqual('ns1.google.com' in dto.response.domain.ns, True)
        self.assertEqual('aspmx.l.google.com' in dto.response.domain.mx, True)

    def testCheckGoodDomainConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        domain_sample = 'google.com'
        connection = client.Client(api_key = api_key_sample)
        dto = connection.CheckDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.response.score, 0)
        self.assertEqual('ns1.google.com' in dto.response.domain.ns, True)
        self.assertEqual('aspmx.l.google.com' in dto.response.domain.mx, True)

    def testCheckGoodDomainConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        domain_sample = 'google.com'
        connection = client.Client(api_key = api_key_sample)
        dto = connection.CheckDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testCheckBadDomainConnectionAnonymous(self):
        domain_sample = 'mailinator.com'
        connection = client.Client()
        dto = connection.CheckDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.response.score, 0)
        self.assertEqual('betty.ns.cloudflare.com' in dto.response.domain.ns, True)
        self.assertEqual('mail.mailinator.com' in dto.response.domain.mx, True)
        self.assertEqual('DEA' in dto.response.domain.blacklist_mx, True)
        self.assertEqual('IVOLO-DED-IP' in dto.response.ip.blacklist, True)

    def testCheckBadDomainConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        domain_sample = 'mailinator.com'
        connection = client.Client(api_key = api_key_sample)
        dto = connection.CheckDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.response.score, 0)
        self.assertEqual('betty.ns.cloudflare.com' in dto.response.domain.ns, True)
        self.assertEqual('mail.mailinator.com' in dto.response.domain.mx, True)
        self.assertEqual('DEA' in dto.response.domain.blacklist_mx, True)
        self.assertEqual('IVOLO-DED-IP' in dto.response.ip.blacklist, True)

    def testCheckBadDomainConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        domain_sample = 'mailinator.com'
        connection = client.Client(api_key = api_key_sample)
        dto = connection.CheckDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def tesCheckGoodBatchDomainConnectionAnonymous(self):
        domain_sample = ['google.com', 'marca.com', 'facebook.com']
        connection = client.Client()
        dto = connection.CheckBatchDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.domain_scoring_list[0].domain, 'google.com')
        self.assertEqual(dto.domain_scoring_list[1].domain, 'marca.com')
        self.assertEqual(dto.domain_scoring_list[2].domain, 'facebook.com')
        self.assertEqual(dto.domain_scoring_list[0].scoring.score, 0)
        self.assertEqual(dto.domain_scoring_list[1].scoring.score, 0)
        self.assertEqual(dto.domain_scoring_list[2].scoring.score, 0)

    def tesCheckGoodBatchDomainConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        domain_sample = ['google.com', 'marca.com', 'facebook.com']
        connection = client.Client(api_key = api_key_sample)
        dto = connection.CheckBatchDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.domain_scoring_list[0].domain, 'google.com')
        self.assertEqual(dto.domain_scoring_list[1].domain, 'marca.com')
        self.assertEqual(dto.domain_scoring_list[2].domain, 'facebook.com')
        self.assertEqual(dto.domain_scoring_list[0].scoring.score, 0)
        self.assertEqual(dto.domain_scoring_list[1].scoring.score, 0)
        self.assertEqual(dto.domain_scoring_list[2].scoring.score, 0)

    def tesCheckGoodBatchDomainConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        domain_sample = ['google.com', 'marca.com', 'facebook.com']
        connection = client.Client(api_key = api_key_sample)
        dto = connection.CheckBatchDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def tesCheckBadBatchDomainConnectionAnonymous(self):
        domain_sample = ['loketa.com', 'mailinator.com', 'zixoa.com']
        connection = client.Client()
        dto = connection.CheckBatchDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.domain_scoring_list[0].domain, 'loketa.com')
        self.assertEqual(dto.domain_scoring_list[1].domain, 'zixoa.com')
        self.assertEqual(dto.domain_scoring_list[2].domain, 'mailinator.com')
        self.assertNotEqual(dto.domain_scoring_list[0].scoring.score, 0)
        self.assertNotEqual(dto.domain_scoring_list[1].scoring.score, 0)
        self.assertNotEqual(dto.domain_scoring_list[2].scoring.score, 0)

    def tesCheckBadBatchDomainConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        domain_sample = ['loketa.com', 'mailinator.com', 'zixoa.com']
        connection = client.Client(api_key = api_key_sample)
        dto = connection.CheckBatchDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.domain_scoring_list[0].domain, 'loketa.com')
        self.assertEqual(dto.domain_scoring_list[1].domain, 'zixoa.com')
        self.assertEqual(dto.domain_scoring_list[2].domain, 'mailinator.com')
        self.assertNotEqual(dto.domain_scoring_list[0].scoring.score, 0)
        self.assertNotEqual(dto.domain_scoring_list[1].scoring.score, 0)
        self.assertNotEqual(dto.domain_scoring_list[2].scoring.score, 0)

    def tesCheckBadBatchDomainConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        domain_sample = ['loketa.com', 'mailinator.com', 'zixoa.com']
        connection = client.Client(api_key = api_key_sample)
        dto = connection.CheckBatchDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testCheckGoodEmailConnectionAnonymous(self):
        email_sample = 'devops@apility.io'
        connection = client.Client()
        dto = connection.CheckEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.response.score, 0)
        self.assertEqual('pam.ns.cloudflare.com' in dto.response.domain.ns, True)
        self.assertEqual('aspmx.l.google.com' in dto.response.domain.mx, True)
        self.assertEqual(dto.response.disposable.is_disposable, False)
        self.assertEqual(dto.response.freemail.is_freemail, False)
        self.assertEqual(dto.response.address.is_role, False)
        self.assertEqual(dto.response.address.is_well_formed, True)
        self.assertEqual(dto.response.smtp.exist_address, True)

    def testCheckGoodEmailConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        email_sample = 'devops@apility.io'
        connection = client.Client(api_key = api_key_sample)
        dto = connection.CheckEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.response.score, 0)
        self.assertEqual('pam.ns.cloudflare.com' in dto.response.domain.ns, True)
        self.assertEqual('aspmx.l.google.com' in dto.response.domain.mx, True)
        self.assertEqual(dto.response.disposable.is_disposable, False)
        self.assertEqual(dto.response.freemail.is_freemail, False)
        self.assertEqual(dto.response.address.is_role, False)
        self.assertEqual(dto.response.address.is_well_formed, True)
        self.assertEqual(dto.response.smtp.exist_address, True)

    def testCheckGoodEmailConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        email_sample = 'devops@apility.io'
        connection = client.Client(api_key = api_key_sample)
        dto = connection.CheckEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testCheckBadEmailConnectionAnonymous(self):
        email_sample = 'test@mailinator.com'
        connection = client.Client()
        dto = connection.CheckEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.response.score, 0)
        self.assertEqual('betty.ns.cloudflare.com' in dto.response.domain.ns, True)
        self.assertEqual('mail.mailinator.com' in dto.response.domain.mx, True)
        self.assertEqual('DEA' in dto.response.domain.blacklist_mx, True)
        self.assertEqual('IVOLO-DED-IP' in dto.response.ip.blacklist, True)
        self.assertEqual(dto.response.disposable.is_disposable, True)
        self.assertEqual(dto.response.address.is_role, False)
        self.assertEqual(dto.response.address.is_well_formed, True)
        self.assertEqual(dto.response.smtp.exist_address, True)

    def testCheckBadEmailConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        email_sample = 'test@mailinator.com'
        connection = client.Client(api_key = api_key_sample)
        dto = connection.CheckEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.response.score, 0)
        self.assertEqual('betty.ns.cloudflare.com' in dto.response.domain.ns, True)
        self.assertEqual('mail.mailinator.com' in dto.response.domain.mx, True)
        self.assertEqual('DEA' in dto.response.domain.blacklist_mx, True)
        self.assertEqual('IVOLO-DED-IP' in dto.response.ip.blacklist, True)
        self.assertEqual(dto.response.disposable.is_disposable, True)
        self.assertEqual(dto.response.address.is_role, False)
        self.assertEqual(dto.response.address.is_well_formed, True)
        self.assertEqual(dto.response.smtp.exist_address, True)

    def testCheckBadEmailConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        email_sample = 'test@mailinator.com'
        connection = client.Client(api_key = api_key_sample)
        dto = connection.CheckEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def tesCheckGoodBatchEmailConnectionAnonymous(self):
        email_sample = ['devops@apility.io']
        connection = client.Client()
        dto = connection.CheckBatchEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.email_scoring_list[0].email, 'devops@apility.io')
        self.assertEqual(dto.email_scoring_list[0].scoring.score, 0)
        self.assertEqual(dto.email_scoring_list[0].scoring.disposable.is_disposable, False)
        self.assertEqual(dto.email_scoring_list[0].scoring.freemail.is_freemail, False)
        self.assertEqual(dto.email_scoring_list[0].scoring.address.is_role, False)
        self.assertEqual(dto.email_scoring_list[0].scoring.address.is_well_formed, True)
        self.assertEqual(dto.email_scoring_list[0].scoring.smtp.exist_address, True)

    def tesCheckGoodBatchEmailConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        email_sample = ['devops@apility.io']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.email_scoring_list[0].email, 'devops@apility.io')
        self.assertEqual(dto.email_scoring_list[0].scoring.score, 0)
        self.assertEqual(dto.email_scoring_list[0].scoring.disposable.is_disposable, False)
        self.assertEqual(dto.email_scoring_list[0].scoring.freemail.is_freemail, False)
        self.assertEqual(dto.email_scoring_list[0].scoring.address.is_role, False)
        self.assertEqual(dto.email_scoring_list[0].scoring.address.is_well_formed, True)
        self.assertEqual(dto.email_scoring_list[0].scoring.smtp.exist_address, True)

    def tesCheckGoodBatchEmailConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        email_sample = ['devops@apility.io']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def tesCheckBadBatchEmailConnectionAnonymous(self):
        email_sample = ['test@mailinator.com']
        connection = client.Client()
        dto = connection.CheckBatchEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.email_scoring_list[0].email, 'test@mailinator.com')
        self.assertNotEqual(dto.email_scoring_list[0].scoring.score, 0)
        self.assertEqual(dto.email_scoring_list[0].scoring.disposable.is_disposable, True)
        self.assertEqual(dto.email_scoring_list[0].scoring.freemail.is_freemail, False)
        self.assertEqual(dto.email_scoring_list[0].scoring.address.is_role, False)
        self.assertEqual(dto.email_scoring_list[0].scoring.address.is_well_formed, True)
        self.assertEqual(dto.email_scoring_list[0].scoring.smtp.exist_address, True)

    def tesCheckBadBatchEmailConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        email_sample = ['test@mailinator.com']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.email_scoring_list[0].email, 'test@mailinator.com')
        self.assertNotEqual(dto.email_scoring_list[0].scoring.score, 0)
        self.assertEqual(dto.email_scoring_list[0].scoring.disposable.is_disposable, True)
        self.assertEqual(dto.email_scoring_list[0].scoring.freemail.is_freemail, False)
        self.assertEqual(dto.email_scoring_list[0].scoring.address.is_role, False)
        self.assertEqual(dto.email_scoring_list[0].scoring.address.is_well_formed, True)
        self.assertEqual(dto.email_scoring_list[0].scoring.smtp.exist_address, True)

    def tesCheckBadBatchEmailConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        email_sample = ['test@mailinator.com']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testASIPAddressConnectionAnonymous(self):
        ip_sample = '8.8.8.8'
        connection = client.Client()
        dto = connection.GetASbyIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.asystem.name, 'Google LLC')
        self.assertEqual(dto.asystem.asn, '15169')

    def testASPrivateIPAddressConnectionAnonymous(self):
        ip_sample = '10.0.0.1'
        connection = client.Client()
        dto = connection.GetASbyIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.not_found)
        self.assertEqual(dto.asystem, None)

    def testASIPAddressConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '8.8.8.8'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASbyIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.asystem.name, 'Google LLC')
        self.assertEqual(dto.asystem.asn, '15169')

    def testASPrivateIPAddressConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '10.0.0.1'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASbyIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.not_found)
        self.assertEqual(dto.asystem, None)

    def testASIPAddressConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        ip_sample = '8.8.8.8'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASbyIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testASPrivateIPAddressConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        ip_sample = '10.0.0.1'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASbyIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testASNumConnectionAnonymous(self):
        asnum_sample = 15169
        connection = client.Client()
        dto = connection.GetASbyNum(asnum_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.asystem.name, 'Google LLC')
        self.assertEqual(dto.asystem.asn, '15169')

    def testBadNumASNumConnectionAnonymous(self):
        try:
            asnum_sample = -300
            connection = client.Client()
            dto = connection.GetASbyNum(asnum_sample)
            self.assertEqual(1,0,'Wrong formated values should return an error.')
        except:
            self.assertEqual(1,1,'Wrong formatted values interrupted execution.')

    def testBadStringASNumConnectionAnonymous(self):
        try:
            asnum_sample = "abcdce"
            connection = client.Client()
            dto = connection.GetASbyNum(asnum_sample)
            self.assertEqual(1,0,'Wrong formated values should return an error.')
        except:
            self.assertEqual(1,1,'Wrong formatted values interrupted execution.')

    def testASNumConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        asnum_sample = 15169
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASbyNum(asnum_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.asystem.name, 'Google LLC')
        self.assertEqual(dto.asystem.asn, '15169')

    def testASNumConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        asnum_sample = 15169
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASbyNum(asnum_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testASBatchIPAddressesConnectionAnonymous(self):
        ip_sample = ['8.8.8.8','9.9.9.9','8.8.4.4']
        connection = client.Client()
        dto = connection.GetASBatchByIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.asystem_ip_list[0].asystem.asn, '15169')
        self.assertEqual(dto.asystem_ip_list[1].asystem.asn, '19281')
        self.assertEqual(dto.asystem_ip_list[2].asystem.asn, '15169')

    def testASBatchIPAddressesConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = ['8.8.8.8','9.9.9.9','8.8.4.4']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASBatchByIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.asystem_ip_list[0].asystem.asn, '15169')
        self.assertEqual(dto.asystem_ip_list[1].asystem.asn, '19281')
        self.assertEqual(dto.asystem_ip_list[2].asystem.asn, '15169')

    def testASBatchIPAddressesConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        ip_sample = ['8.8.8.8','9.9.9.9','8.8.4.4']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASBatchByIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testASBatchNumConnectionAnonymous(self):
        asn_sample = [15169, 19281]
        connection = client.Client()
        dto = connection.GetASBatchByNum(asn_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.asystem_asn_list[0].asystem.asn, '15169')
        self.assertEqual(dto.asystem_asn_list[1].asystem.asn, '19281')

    def testASBatchNumConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        asn_sample = [15169, 19281]
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASBatchByNum(asn_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.asystem_asn_list[0].asystem.asn, '15169')
        self.assertEqual(dto.asystem_asn_list[1].asystem.asn, '19281')

    def testASBatchNumConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        asn_sample = [15169, 19281]
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASBatchByNum(asn_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testWhoisIPAddressConnectionAnonymous(self):
        ip_sample = '8.8.8.8'
        connection = client.Client()
        dto = connection.GetWhoisIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.whois.entities[0], 'GOGL')
        self.assertEqual(dto.whois.asn, '15169')

    def testWhoisIPAddressConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '9.9.9.9'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetWhoisIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.whois.entities[0], 'CLEAN-97')
        self.assertEqual(dto.whois.asn, '19281')

    def testWhoisIPAddressConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        ip_sample = '9.9.9.9'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetWhoisIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testHistoryIPAddressConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '1.2.3.4'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetHistoryIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.history[0].ip, '1.2.3.4')
        self.assertEqual(len(dto.history[0].blacklist_change)>0, True)

    def testHistoryIPAddressConnectionAnonymous(self):
        ip_sample = '1.2.3.4'
        connection = client.Client()
        dto = connection.GetHistoryIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.unauthorized)

    def testHistoryDomainConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        domain = 'mailinator.com'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetHistoryDomain(domain)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.history[0].domain, 'mailinator.com')
        self.assertEqual(len(dto.history[0].blacklist_change)>0, True)
        print(dto.history)

    def testHistoryDomainConnectionAnonymous(self):
        domain = 'mailinator.com'
        connection = client.Client()
        dto = connection.GetHistoryDomain(domain)
        self.assertEqual(dto.status_code, requests.codes.unauthorized)

    def testHistoryEmailConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        email = 'test@mailinator.com'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetHistoryEmail(email)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.history[0].email, 'test@mailinator.com')
        self.assertEqual(len(dto.history[0].blacklist_change)>0, True)

    def testHistoryEmailConnectionAnonymous(self):
        email = 'test@mailinator.com'
        connection = client.Client()
        dto = connection.GetHistoryEmail(email)
        self.assertEqual(dto.status_code, requests.codes.unauthorized)

    def testQuarantineIPAddressConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetQuarantineIP()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.ip == '1.2.3.4':
                self.assertEqual(obj.ip, '1.2.3.4')
                self.assertEqual(obj.ttl, -1)
                return
        self.assertNotEqual(dto.error, None)

    def testQuarantineCountryConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetQuarantineCountry()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.country == 'AQ':
                self.assertEqual(obj.country, 'AQ')
                self.assertEqual(obj.ttl, -1)
                return
        self.assertNotEqual(dto.error, None)

    def testQuarantineContinentConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetQuarantineContinent()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.continent == 'AN':
                self.assertEqual(obj.continent, 'AN')
                self.assertEqual(obj.ttl, -1)
                return
        self.assertNotEqual(dto.error, None)

    def testQuarantineASConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetQuarantineAS()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.asn == '360000':
                self.assertEqual(obj.asn, '360000')
                self.assertEqual(obj.ttl, -1)
                return
        self.assertNotEqual(dto.error, None)

    def testAddQuarantineIPAddressDefaultTTLConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '9.9.9.9'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.AddQuarantineIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        dto = connection.GetQuarantineIP()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.ip == '9.9.9.9':
                self.assertEqual(obj.ip, '9.9.9.9')
                self.assertEqual(obj.ttl, 3600)
                return
        self.assertNotEqual(dto.error, None)

    def testAddQuarantineCountryDefaultTTLConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        country = 'pn'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.AddQuarantineCountry(country)
        self.assertEqual(dto.status_code, requests.codes.ok)
        dto = connection.GetQuarantineCountry()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.country == 'PN':
                self.assertEqual(obj.country, 'PN')
                self.assertEqual(obj.ttl, 3600)
                return
        self.assertNotEqual(dto.error, None)

    def testAddQuarantineContinentDefaultTTLConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        continent = 'AN'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.AddQuarantineContinent(continent)
        self.assertEqual(dto.status_code, requests.codes.ok)
        dto = connection.GetQuarantineContinent()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.continent == 'AN':
                self.assertEqual(obj.continent, 'AN')
                self.assertEqual(obj.ttl, 3600)
                return
        self.assertNotEqual(dto.error, None)

    def testAddQuarantineASDefaultTTLConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        asnum = 360000
        connection = client.Client(api_key=api_key_sample)
        dto = connection.AddQuarantineAS(asnum)
        self.assertEqual(dto.status_code, requests.codes.ok)
        dto = connection.GetQuarantineAS()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.asn == '360000':
                self.assertEqual(obj.asn, '360000')
                self.assertEqual(obj.ttl, 3600)
                return
        self.assertNotEqual(dto.error, None)

    def testDeleteQuarantineIPAddressConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '9.9.9.9'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.AddQuarantineIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)

        dto = connection.DeleteQuarantineIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)

        time.sleep(2)
        dto = connection.GetQuarantineIP()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.ip == '9.9.9.9':
                self.assertNotEqual(dto.error, None)
                return
        self.assertEqual(dto.error, None)

    def testDeleteQuarantineCountryConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        country = 'pn'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.AddQuarantineCountry(country)
        self.assertEqual(dto.status_code, requests.codes.ok)

        dto = connection.DeleteQuarantineCountry(country)
        self.assertEqual(dto.status_code, requests.codes.ok)

        time.sleep(2)
        dto = connection.GetQuarantineCountry()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.country == 'PN':
                self.assertNotEqual(dto.error, None)
                return
        self.assertEqual(dto.error, None)

    def testDeleteQuarantineContinentConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        continent = 'an'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.AddQuarantineContinent(continent)
        self.assertEqual(dto.status_code, requests.codes.ok)

        dto = connection.DeleteQuarantineContinent(continent)
        self.assertEqual(dto.status_code, requests.codes.ok)

        time.sleep(2)
        dto = connection.GetQuarantineContinent()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.continent == 'AN':
                self.assertNotEqual(dto.error, None)
                return
        self.assertEqual(dto.error, None)

    def testDeleteQuarantineASConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        asn = 360000
        connection = client.Client(api_key=api_key_sample)
        dto = connection.AddQuarantineAS(asn)
        self.assertEqual(dto.status_code, requests.codes.ok)

        dto = connection.DeleteQuarantineAS(asn)
        self.assertEqual(dto.status_code, requests.codes.ok)

        time.sleep(2)
        dto = connection.GetQuarantineAS()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.asn == '360000':
                self.assertNotEqual(dto.error, None)
                return
        self.assertEqual(dto.error, None)

#if __name__ == '__main__':
#    unittest.main()