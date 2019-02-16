"""
Copyright 2017-2018 CAPITAL LAB OU

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import unittest
import requests
import time
import os

import apilityio.client as client
import apilityio.common as common

TEST_WRONG_KEY_SAMPLE = '123dcfe6-63d3-3cd2-b427-75d1b1c117ed'


# To test the API, you have to pass a valid API KEY as an exported environment variable first:
# export APILITYIO_API_KEY=<YOUR_API_KEY>
# You can get an API KEY for free registering in APILITYIO_API_KEY

TEST_KEY_SAMPLE = os.environ['APILITYIO_API_KEY']


class ClientTestCase(unittest.TestCase):

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
        connection = client.Client(host=host_sample)
        api_key_test, protocol_test, host_test = connection.GetConnectionData()
        self.assertEqual(api_key_test, None)
        self.assertEqual(protocol_test, common.HTTPS_PROTOCOL)
        self.assertEqual(host_test, host_sample)

    def testCheckBadIPAddressConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '1.2.3.4'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.blacklists, [])

    def testCheckBadIPAddressConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '1.2.3.4'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertIn('QUARANTINE-IP', dto.json['response'])

    def testCheckBadIPAddressConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        ip_sample = '1.2.3.4'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testCheckBadBatchIPAddressConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = ['1.2.3.4', '114.223.63.139', '114.224.29.97']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.ipblacklists_set, None)
        self.assertEqual(3, len(dto.json['response']))

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

    def testGeoIPAddressConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '8.8.8.8'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetGeoIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.geoip.address, '8.8.8.8')
        self.assertEqual(dto.geoip.asystem.asn, '15169')

    def testGeoIPAddressConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '8.8.8.8'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetGeoIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.geoip.address, '8.8.8.8')
        self.assertEqual(dto.geoip.asystem.asn, '15169')
        self.assertEqual('US', dto.json['ip']['country'])

    def testGeoIPAddressConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        ip_sample = '8.8.8.8'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetGeoIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testGeoBatchIPAddressesConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = ['8.8.8.8', '9.9.9.9', '8.8.4.4']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetGeoBatchIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(
            dto.geolocated_ip_list[0].geoip.address, dto.geolocated_ip_list[0].ip_address)
        self.assertEqual(
            dto.geolocated_ip_list[1].geoip.address, dto.geolocated_ip_list[1].ip_address)
        self.assertEqual(
            dto.geolocated_ip_list[2].geoip.address, dto.geolocated_ip_list[2].ip_address)

    def testGeoBatchIPAddressesConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = ['8.8.8.8', '9.9.9.9', '8.8.4.4']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetGeoBatchIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(
            dto.geolocated_ip_list[0].geoip.address, dto.geolocated_ip_list[0].ip_address)
        self.assertEqual(
            dto.geolocated_ip_list[1].geoip.address, dto.geolocated_ip_list[1].ip_address)
        self.assertEqual(
            dto.geolocated_ip_list[2].geoip.address, dto.geolocated_ip_list[2].ip_address)
        self.assertEqual(3, len(dto.json['response']))

    def testGeoBatchIPAddressesConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        ip_sample = ['8.8.8.8', '9.9.9.9', '8.8.4.4']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetGeoBatchIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testCheckGoodDomainConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        domain_sample = 'google.com'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.response.score, 0)
        self.assertEqual('ns1.google.com' in dto.response.domain.ns, True)
        self.assertEqual('aspmx.l.google.com' in dto.response.domain.mx, True)

    def testCheckGoodDomainConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        domain_sample = 'google.com'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testCheckBadDomainConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        domain_sample = 'mailinator.com'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.response.score, 0)
        self.assertEqual(
            'betty.ns.cloudflare.com' in dto.response.domain.ns, True)
        self.assertEqual('mail.mailinator.com' in dto.response.domain.mx, True)
        self.assertEqual('DEA' in dto.response.domain.blacklist_mx, True)
        self.assertEqual('IVOLO-DED-IP' in dto.response.ip.blacklist, True)

    def testCheckBadDomainConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        domain_sample = 'mailinator.com'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.response.score, 0)
        self.assertEqual(
            'betty.ns.cloudflare.com' in dto.response.domain.ns, True)
        self.assertEqual('mail.mailinator.com' in dto.response.domain.mx, True)
        self.assertEqual('DEA' in dto.response.domain.blacklist_mx, True)
        self.assertEqual('IVOLO-DED-IP' in dto.response.ip.blacklist, True)
        self.assertEqual(-2, dto.json['response']['score'])

    def testCheckBadDomainConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        domain_sample = 'mailinator.com'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def tesCheckGoodBatchDomainConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        domain_sample = ['google.com', 'marca.com', 'facebook.com']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertIn(dto.domain_scoring_list[0].domain, [
                      'google.com', 'marca.com', 'facebook.com'])
        self.assertIn(dto.domain_scoring_list[1].domain, [
                      'google.com', 'marca.com', 'facebook.com'])
        self.assertIn(dto.domain_scoring_list[2].domain, [
                      'google.com', 'marca.com', 'facebook.com'])
        self.assertEqual(dto.domain_scoring_list[0].scoring.score, 0)
        self.assertEqual(dto.domain_scoring_list[1].scoring.score, 0)
        self.assertEqual(dto.domain_scoring_list[2].scoring.score, 0)

    def tesCheckGoodBatchDomainConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        domain_sample = ['google.com', 'marca.com', 'facebook.com']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertIn(dto.domain_scoring_list[0].domain, [
                      'google.com', 'marca.com', 'facebook.com'])
        self.assertIn(dto.domain_scoring_list[1].domain, [
                      'google.com', 'marca.com', 'facebook.com'])
        self.assertIn(dto.domain_scoring_list[2].domain, [
                      'google.com', 'marca.com', 'facebook.com'])
        self.assertEqual(dto.domain_scoring_list[0].scoring.score, 0)
        self.assertEqual(dto.domain_scoring_list[1].scoring.score, 0)
        self.assertEqual(dto.domain_scoring_list[2].scoring.score, 0)
        self.assertEqual(3, len(dto.json['response']))

    def tesCheckGoodBatchDomainConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        domain_sample = ['google.com', 'marca.com', 'facebook.com']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def tesCheckBadBatchDomainConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        domain_sample = ['loketa.com', 'mailinator.com', 'zixoa.com']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertIn(dto.domain_scoring_list[0].domain, [
                      'loketa.com', 'mailinator.com', 'zixoa.com'])
        self.assertIn(dto.domain_scoring_list[1].domain, [
                      'loketa.com', 'mailinator.com', 'zixoa.com'])
        self.assertIn(dto.domain_scoring_list[2].domain, [
                      'loketa.com', 'mailinator.com', 'zixoa.com'])
        self.assertNotEqual(dto.domain_scoring_list[0].scoring.score, 0)
        self.assertNotEqual(dto.domain_scoring_list[1].scoring.score, 0)
        self.assertNotEqual(dto.domain_scoring_list[2].scoring.score, 0)

    def tesCheckBadBatchDomainConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        domain_sample = ['loketa.com', 'mailinator.com', 'zixoa.com']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testCheckGoodEmailConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        email_sample = 'devops@apility.io'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.response.score, 0)
        self.assertEqual(
            'pam.ns.cloudflare.com' in dto.response.domain.ns, True)
        self.assertEqual('aspmx.l.google.com' in dto.response.domain.mx, True)
        self.assertEqual(dto.response.disposable.is_disposable, False)
        self.assertEqual(dto.response.freemail.is_freemail, False)
        self.assertEqual(dto.response.address.is_role, False)
        self.assertEqual(dto.response.address.is_well_formed, True)
        self.assertEqual(dto.response.smtp.exist_address, True)

    def testCheckGoodEmailConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        email_sample = 'devops@apility.io'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testCheckBadEmailConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        email_sample = 'test@mailinator.com'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.response.score, 0)
        self.assertEqual(
            'betty.ns.cloudflare.com' in dto.response.domain.ns, True)
        self.assertEqual('mail.mailinator.com' in dto.response.domain.mx, True)
        self.assertEqual('DEA' in dto.response.domain.blacklist_mx, True)
        self.assertEqual('IVOLO-DED-IP' in dto.response.ip.blacklist, True)
        self.assertEqual(dto.response.disposable.is_disposable, True)
        self.assertEqual(dto.response.address.is_role, False)
        self.assertEqual(dto.response.address.is_well_formed, True)
        self.assertEqual(dto.response.smtp.exist_address, True)

    def testCheckBadEmailConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        email_sample = 'test@mailinator.com'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.response.score, 0)
        self.assertEqual(
            'betty.ns.cloudflare.com' in dto.response.domain.ns, True)
        self.assertEqual('mail.mailinator.com' in dto.response.domain.mx, True)
        self.assertEqual('DEA' in dto.response.domain.blacklist_mx, True)
        self.assertEqual('IVOLO-DED-IP' in dto.response.ip.blacklist, True)
        self.assertEqual(dto.response.disposable.is_disposable, True)
        self.assertEqual(dto.response.address.is_role, False)
        self.assertEqual(dto.response.address.is_well_formed, True)
        self.assertEqual(dto.response.smtp.exist_address, True)
        self.assertEqual(-3, dto.json['response']['score'])

    def testCheckBadEmailConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        email_sample = 'test@mailinator.com'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def tesCheckGoodBatchEmailConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        email_sample = ['devops@apility.io']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.email_scoring_list[0].email, 'devops@apility.io')
        self.assertEqual(dto.email_scoring_list[0].scoring.score, 0)
        self.assertEqual(
            dto.email_scoring_list[0].scoring.disposable.is_disposable, False)
        self.assertEqual(
            dto.email_scoring_list[0].scoring.freemail.is_freemail, False)
        self.assertEqual(
            dto.email_scoring_list[0].scoring.address.is_role, False)
        self.assertEqual(
            dto.email_scoring_list[0].scoring.address.is_well_formed, True)
        self.assertEqual(
            dto.email_scoring_list[0].scoring.smtp.exist_address, True)

    def tesCheckGoodBatchEmailConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        email_sample = ['devops@apility.io']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def tesCheckBadBatchEmailConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        email_sample = ['test@mailinator.com']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(
            dto.email_scoring_list[0].email, 'test@mailinator.com')
        self.assertNotEqual(dto.email_scoring_list[0].scoring.score, 0)
        self.assertEqual(
            dto.email_scoring_list[0].scoring.disposable.is_disposable, True)
        self.assertEqual(
            dto.email_scoring_list[0].scoring.freemail.is_freemail, False)
        self.assertEqual(
            dto.email_scoring_list[0].scoring.address.is_role, False)
        self.assertEqual(
            dto.email_scoring_list[0].scoring.address.is_well_formed, True)
        self.assertEqual(
            dto.email_scoring_list[0].scoring.smtp.exist_address, True)

    def tesCheckBadBatchEmailConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        email_sample = ['test@mailinator.com']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(
            dto.email_scoring_list[0].email, 'test@mailinator.com')
        self.assertNotEqual(dto.email_scoring_list[0].scoring.score, 0)
        self.assertEqual(
            dto.email_scoring_list[0].scoring.disposable.is_disposable, True)
        self.assertEqual(
            dto.email_scoring_list[0].scoring.freemail.is_freemail, False)
        self.assertEqual(
            dto.email_scoring_list[0].scoring.address.is_role, False)
        self.assertEqual(
            dto.email_scoring_list[0].scoring.address.is_well_formed, True)
        self.assertEqual(
            dto.email_scoring_list[0].scoring.smtp.exist_address, True)
        self.assertEqual(1, len(dto.json['response']))

    def tesCheckBadBatchEmailConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        email_sample = ['test@mailinator.com']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.CheckBatchEmail(email_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testASIPAddressConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '8.8.8.8'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASbyIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.asystem.name, 'Google LLC')
        self.assertEqual(dto.asystem.asn, '15169')

    def testASIPAddressConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '8.8.8.8'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASbyIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.asystem.name, 'Google LLC')
        self.assertEqual(dto.asystem.asn, '15169')
        self.assertEqual(dto.json['as']['asn'], '15169')

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

    def testASNumConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        asnum_sample = 15169
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASbyNum(asnum_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.asystem.name, 'Google LLC')
        self.assertEqual(dto.asystem.asn, '15169')
        self.assertEqual(dto.json['as']['asn'], '15169')

    def testASNumConnectionApiKeyJSON(self):
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

    def testASBatchIPAddressesConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = ['8.8.8.8', '9.9.9.9', '8.8.4.4']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASBatchByIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertIn(dto.asystem_ip_list[0].asystem.asn, ['15169', '19281'])
        self.assertIn(dto.asystem_ip_list[1].asystem.asn, ['15169', '19281'])
        self.assertIn(dto.asystem_ip_list[2].asystem.asn, ['15169', '19281'])

    def testASBatchIPAddressesConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = ['8.8.8.8', '9.9.9.9', '8.8.4.4']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASBatchByIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertIn(dto.asystem_ip_list[0].asystem.asn, ['15169', '19281'])
        self.assertIn(dto.asystem_ip_list[1].asystem.asn, ['15169', '19281'])
        self.assertIn(dto.asystem_ip_list[2].asystem.asn, ['15169', '19281'])
        self.assertEqual(3, len(dto.json['response']))

    def testASBatchIPAddressesConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        ip_sample = ['8.8.8.8', '9.9.9.9', '8.8.4.4']
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASBatchByIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testASBatchNumConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        asn_sample = [15169, 19281]
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASBatchByNum(asn_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertIn(dto.asystem_asn_list[0].asystem.asn, ['15169', '19281'])
        self.assertIn(dto.asystem_asn_list[1].asystem.asn, ['15169', '19281'])

    def testASBatchNumConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        asn_sample = [15169, 19281]
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASBatchByNum(asn_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertIn(dto.asystem_asn_list[0].asystem.asn, ['15169', '19281'])
        self.assertIn(dto.asystem_asn_list[1].asystem.asn, ['15169', '19281'])
        self.assertEqual(2, len(dto.json['response']))

    def testASBatchNumConnectionWrongApiKey(self):
        api_key_sample = TEST_WRONG_KEY_SAMPLE
        asn_sample = [15169, 19281]
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetASBatchByNum(asn_sample)
        self.assertEqual(dto.status_code, requests.codes.bad_request)

    def testWhoisIPAddressConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '9.9.9.9'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetWhoisIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.whois.entities[0], 'CLEAN-97')
        self.assertEqual(dto.whois.asn, '19281')

    def testWhoisIPAddressConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '9.9.9.9'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetWhoisIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.whois.entities[0], 'CLEAN-97')
        self.assertEqual(dto.whois.asn, '19281')
        self.assertEqual('19281', dto.json['whois']['asn'])

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
        self.assertEqual(len(dto.history[0].blacklist_change) > 0, True)

    def testHistoryIPAddressConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '1.2.3.4'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetHistoryIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.history[0].ip, '1.2.3.4')
        self.assertEqual(len(dto.history[0].blacklist_change) > 0, True)
        self.assertGreater(len(dto.json['changes_ip']), 0)

    def testHistoryDomainConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        domain = 'mailinator.com'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetHistoryDomain(domain)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.history[0].domain, 'mailinator.com')
        self.assertEqual(len(dto.history[0].blacklist_change) > 0, True)

    def testHistoryDomainConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        domain = 'mailinator.com'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetHistoryDomain(domain)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.history[0].domain, 'mailinator.com')
        self.assertEqual(len(dto.history[0].blacklist_change) > 0, True)
        self.assertGreater(len(dto.json['changes_domain']), 0)

    def testHistoryEmailConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        email = 'test@mailinator.com'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetHistoryEmail(email)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.history[0].email, 'test@mailinator.com')
        self.assertEqual(len(dto.history[0].blacklist_change) > 0, True)

    def testHistoryEmailConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        email = 'test@mailinator.com'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetHistoryEmail(email)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.history[0].email, 'test@mailinator.com')
        self.assertEqual(len(dto.history[0].blacklist_change) > 0, True)
        self.assertGreater(len(dto.json['changes_email']), 0)

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

    def testQuarantineIPAddressConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetQuarantineIP()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.ip == '1.2.3.4':
                self.assertEqual(obj.ip, '1.2.3.4')
                self.assertEqual(obj.ttl, -1)
                self.assertGreater(len(dto.json['quarantined']), 0)
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

    def testQuarantineCountryConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        connection = client.Client(api_key=api_key_sample)
        dto = connection.GetQuarantineCountry()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.country == 'AQ':
                self.assertEqual(obj.country, 'AQ')
                self.assertEqual(obj.ttl, -1)
                self.assertGreater(len(dto.json['quarantined']), 0)
                return
        self.assertNotEqual(dto.error, None)

    def testQuarantineContinentConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        connection = client.Client(api_key=api_key_sample)

        continent = 'an'
        dto = connection.AddQuarantineContinent(continent)
        self.assertEqual(dto.status_code, requests.codes.ok)


        for x in range(0,10):
            time.sleep(2)
            dto = connection.GetQuarantineContinent()
            self.assertEqual(dto.status_code, requests.codes.ok)
            self.assertEqual(dto.error, None)
            for obj in dto.quarantine:
                if obj.continent == 'AN':
                    self.assertEqual(obj.continent, 'AN')
                    self.assertLessEqual(obj.ttl, 3600)
                    dto = connection.DeleteQuarantineContinent(continent)
                    self.assertEqual(dto.status_code, requests.codes.ok)
                    return
        self.assertNotEqual(dto.error, None)

        dto = connection.DeleteQuarantineContinent(continent)
        self.assertEqual(dto.status_code, requests.codes.ok)

    def testQuarantineContinentConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        connection = client.Client(api_key=api_key_sample)

        continent = 'an'
        dto = connection.AddQuarantineContinent(continent)
        self.assertEqual(dto.status_code, requests.codes.ok)

        for x in range(0,10):
            time.sleep(2)
            dto = connection.GetQuarantineContinent()
            self.assertEqual(dto.status_code, requests.codes.ok)
            self.assertEqual(dto.error, None)
            for obj in dto.quarantine:
                if obj.continent == 'AN':
                    self.assertEqual(obj.continent, 'AN')
                    self.assertLessEqual(obj.ttl, 3600)

                    self.assertGreater(len(dto.json['quarantined']), 0)

                    dto = connection.DeleteQuarantineContinent(continent)
                    self.assertEqual(dto.status_code, requests.codes.ok)
                    return
        self.assertNotEqual(dto.error, None)

        dto = connection.DeleteQuarantineContinent(continent)
        self.assertEqual(dto.status_code, requests.codes.ok)

    def testQuarantineASConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        connection = client.Client(api_key=api_key_sample)

        asn = 360000
        dto = connection.AddQuarantineAS(asn)
        self.assertEqual(dto.status_code, requests.codes.ok)

        for x in range(0,10):
            time.sleep(2)
            dto = connection.GetQuarantineAS()
            self.assertEqual(dto.status_code, requests.codes.ok)
            self.assertEqual(dto.error, None)
            for obj in dto.quarantine:
                if obj.asn == '360000':
                    self.assertEqual(obj.asn, '360000')
                    self.assertLessEqual(obj.ttl, 3600)
                    return
        self.assertNotEqual(dto.error, None)

        dto = connection.DeleteQuarantineAS(asn)
        self.assertEqual(dto.status_code, requests.codes.ok)

    def testQuarantineASConnectionApiKeyJSON(self):
        api_key_sample = TEST_KEY_SAMPLE
        connection = client.Client(api_key=api_key_sample)

        asn = 360000
        dto = connection.AddQuarantineAS(asn)
        self.assertEqual(dto.status_code, requests.codes.ok)

        for x in range(0,10):
            time.sleep(2)
            dto = connection.GetQuarantineAS()
            self.assertEqual(dto.status_code, requests.codes.ok)
            self.assertEqual(dto.error, None)
            for obj in dto.quarantine:
                if obj.asn == '360000':
                    self.assertEqual(obj.asn, '360000')
                    self.assertLessEqual(obj.ttl, 3600)

                    self.assertGreater(len(dto.json['quarantined']), 0)

                    dto = connection.DeleteQuarantineAS(asn)
                    self.assertEqual(dto.status_code, requests.codes.ok)
                    return
        self.assertNotEqual(dto.error, None)

        dto = connection.DeleteQuarantineAS(asn)
        self.assertEqual(dto.status_code, requests.codes.ok)

    def testAddQuarantineIPAddressDefaultTTLConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '9.9.9.9'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.AddQuarantineIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)

        time.sleep(2)

        dto = connection.GetQuarantineIP()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.ip == '9.9.9.9':
                self.assertEqual(obj.ip, '9.9.9.9')
                self.assertLessEqual(obj.ttl, 3600)
                return
        self.assertNotEqual(dto.error, None)

    def testAddQuarantineCountryDefaultTTLConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        country = 'pn'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.AddQuarantineCountry(country)
        self.assertEqual(dto.status_code, requests.codes.ok)

        time.sleep(2)

        dto = connection.GetQuarantineCountry()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.country == 'PN':
                self.assertEqual(obj.country, 'PN')
                self.assertLessEqual(obj.ttl, 3600)
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
                self.assertLessEqual(obj.ttl, 3600)
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
                self.assertLessEqual(obj.ttl, 3600)
                return
        self.assertNotEqual(dto.error, None)

    def testDeleteQuarantineIPAddressConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        ip_sample = '9.9.9.9'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.AddQuarantineIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)

        time.sleep(2)
        dto = connection.DeleteQuarantineIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)

        time.sleep(5)
        dto = connection.GetQuarantineIP()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.ip == '9.9.9.9':
                self.assertTrue(True)
                return
        self.assertEqual(dto.error, None)

    def testDeleteQuarantineCountryConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        country = 'pn'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.AddQuarantineCountry(country)
        self.assertEqual(dto.status_code, requests.codes.ok)

        time.sleep(2)
        dto = connection.DeleteQuarantineCountry(country)
        self.assertEqual(dto.status_code, requests.codes.ok)

        time.sleep(5)
        dto = connection.GetQuarantineCountry()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.country == 'PN':
                self.assertTrue(True)
                return
        self.assertEqual(dto.error, None)

    def testDeleteQuarantineContinentConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        continent = 'an'
        connection = client.Client(api_key=api_key_sample)
        dto = connection.AddQuarantineContinent(continent)
        self.assertEqual(dto.status_code, requests.codes.ok)

        time.sleep(2)
        dto = connection.DeleteQuarantineContinent(continent)
        self.assertEqual(dto.status_code, requests.codes.ok)

        time.sleep(5)
        dto = connection.GetQuarantineContinent()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.continent == 'AN':
                self.assertTrue(True)
                return
        self.assertEqual(dto.error, None)

    def testDeleteQuarantineASConnectionApiKey(self):
        api_key_sample = TEST_KEY_SAMPLE
        asn = 360000
        connection = client.Client(api_key=api_key_sample)
        dto = connection.AddQuarantineAS(asn)
        self.assertEqual(dto.status_code, requests.codes.ok)

        time.sleep(2)
        dto = connection.DeleteQuarantineAS(asn)
        self.assertEqual(dto.status_code, requests.codes.ok)

        time.sleep(5)
        dto = connection.GetQuarantineAS()
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        for obj in dto.quarantine:
            if obj.asn == '360000':
                self.assertTrue(True)
                return
        self.assertEqual(dto.error, None)

# if __name__ == '__main__':
#    unittest.main()
