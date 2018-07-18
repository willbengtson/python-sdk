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

import apilityio.client as client


class ClientTestCase(unittest.TestCase):

    def setUp(self):
        # This is a test
        x = 1

    def tearDown(self):
        #This is anothertest
        x = 2

    def testCheckGoodIPAddressConnectionAnonymous(self):
        ip_sample = '8.8.8.8'
        connection = client.Client()
        dto = connection.CheckIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.not_found)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.blacklists, [])
        time.sleep(10)

    def testCheckBadIPAddressConnectionAnonymous(self):
        ip_sample = '1.2.3.4'
        connection = client.Client()
        dto = connection.CheckIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.blacklists, [])
        time.sleep(10)

    def testCheckGoodBatchIPAddressesConnectionAnonymous(self):
        ip_sample = ['8.8.8.8','9.9.9.9','8.8.4.4']
        connection = client.Client()
        dto = connection.CheckBatchIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.ipblacklists_set, None)
        time.sleep(10)

    def testCheckBadBatchIPAddressesConnectionAnonymous(self):
        ip_sample = ['1.2.3.4', '114.223.63.139', '114.224.29.97']
        connection = client.Client()
        dto = connection.CheckBatchIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertNotEqual(dto.ipblacklists_set, None)
        time.sleep(10)

    def testCheckBadBatchIPAddressesWrongFormatConnectionAnonymous(self):
        ip_sample = ['1.2.3.4', 'abcdef', 'mdmdmdmdm']
        connection = client.Client()
        try:
            dto = connection.CheckBatchIP(ip_sample)
            self.assertEqual(1,0,'Wrong formated values should return an error.')
        except:
            self.assertEqual(1,1,'Wrong formatted values interrupted execution.')
        time.sleep(10)

    def testGeoIPAddressConnectionAnonymous(self):
        ip_sample = '8.8.8.8'
        connection = client.Client()
        dto = connection.GetGeoIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.geoip.address, '8.8.8.8')
        self.assertEqual(dto.geoip.asystem.asn, '15169')
        time.sleep(10)

    def testGeoPrivateIPAddressConnectionAnonymous(self):
        ip_sample = '10.0.0.1'
        connection = client.Client()
        dto = connection.GetGeoIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.geoip, None)
        time.sleep(10)

    def testGeoBatchIPAddressesConnectionAnonymous(self):
        ip_sample = ['8.8.8.8','9.9.9.9','8.8.4.4']
        connection = client.Client()
        dto = connection.GetGeoBatchIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.geolocated_ip_list[0].geoip.address, dto.geolocated_ip_list[0].ip_address)
        self.assertEqual(dto.geolocated_ip_list[1].geoip.address, dto.geolocated_ip_list[1].ip_address)
        self.assertEqual(dto.geolocated_ip_list[2].geoip.address, dto.geolocated_ip_list[2].ip_address)
        time.sleep(10)

    def testCheckGoodDomainConnectionAnonymous(self):
        domain_sample = 'google.com'
        connection = client.Client()
        dto = connection.CheckDomain(domain_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.response.score, 0)
        self.assertEqual('ns1.google.com' in dto.response.domain.ns, True)
        self.assertEqual('aspmx.l.google.com' in dto.response.domain.mx, True)
        time.sleep(10)

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
        time.sleep(10)

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
        time.sleep(10)

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
        time.sleep(10)

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
        time.sleep(10)

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
        time.sleep(10)

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
        time.sleep(10)

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
        time.sleep(10)

    def testASIPAddressConnectionAnonymous(self):
        ip_sample = '8.8.8.8'
        connection = client.Client()
        dto = connection.GetASbyIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.asystem.name, 'Google LLC')
        self.assertEqual(dto.asystem.asn, '15169')
        time.sleep(10)

    def testASPrivateIPAddressConnectionAnonymous(self):
        ip_sample = '10.0.0.1'
        connection = client.Client()
        dto = connection.GetASbyIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.not_found)
        self.assertEqual(dto.asystem, None)
        time.sleep(10)

    def testASNumConnectionAnonymous(self):
        asnum_sample = 15169
        connection = client.Client()
        dto = connection.GetASbyNum(asnum_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.asystem.name, 'Google LLC')
        self.assertEqual(dto.asystem.asn, '15169')
        time.sleep(10)

    def testBadNumASNumConnectionAnonymous(self):
        try:
            asnum_sample = -300
            connection = client.Client()
            dto = connection.GetASbyNum(asnum_sample)
            self.assertEqual(1,0,'Wrong formated values should return an error.')
        except:
            self.assertEqual(1,1,'Wrong formatted values interrupted execution.')
        time.sleep(10)

    def testBadStringASNumConnectionAnonymous(self):
        try:
            asnum_sample = "abcdce"
            connection = client.Client()
            dto = connection.GetASbyNum(asnum_sample)
            self.assertEqual(1,0,'Wrong formated values should return an error.')
        except:
            self.assertEqual(1,1,'Wrong formatted values interrupted execution.')
        time.sleep(10)

    def testASBatchIPAddressesConnectionAnonymous(self):
        ip_sample = ['8.8.8.8','9.9.9.9','8.8.4.4']
        connection = client.Client()
        dto = connection.GetASBatchByIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.asystem_ip_list[0].asystem.asn, '15169')
        self.assertEqual(dto.asystem_ip_list[1].asystem.asn, '19281')
        self.assertEqual(dto.asystem_ip_list[2].asystem.asn, '15169')
        time.sleep(10)

    def testASBatchNumConnectionAnonymous(self):
        asn_sample = [15169, 19281]
        connection = client.Client()
        dto = connection.GetASBatchByNum(asn_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.asystem_asn_list[0].asystem.asn, '15169')
        self.assertEqual(dto.asystem_asn_list[1].asystem.asn, '19281')
        time.sleep(10)

    def testWhoisIPAddressConnectionAnonymous(self):
        ip_sample = '8.8.8.8'
        connection = client.Client()
        dto = connection.GetWhoisIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.ok)
        self.assertEqual(dto.error, None)
        self.assertEqual(dto.whois.entities[0], 'GOGL')
        self.assertEqual(dto.whois.asn, '15169')
        time.sleep(10)

    def testHistoryIPAddressConnectionAnonymous(self):
        ip_sample = '1.2.3.4'
        connection = client.Client()
        dto = connection.GetHistoryIP(ip_sample)
        self.assertEqual(dto.status_code, requests.codes.unauthorized)
        time.sleep(10)

    def testHistoryDomainConnectionAnonymous(self):
        domain = 'mailinator.com'
        connection = client.Client()
        dto = connection.GetHistoryDomain(domain)
        self.assertEqual(dto.status_code, requests.codes.unauthorized)
        time.sleep(10)

    def testHistoryEmailConnectionAnonymous(self):
        email = 'test@mailinator.com'
        connection = client.Client()
        dto = connection.GetHistoryEmail(email)
        self.assertEqual(dto.status_code, requests.codes.unauthorized)
        time.sleep(10)


#if __name__ == '__main__':
#    unittest.main()