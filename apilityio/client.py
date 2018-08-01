# Copyright 2017-2018 CAPITAL LAB OU
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
client module
-------------

This module contains the class Client that implements all the logic of the client to connect to the API services of
Apility.io.

All the methods return an Object that encapsulates the HTTP response status code, the error (if any),
and the collection of objects needed.

"""

import ipaddress
import requests
import logging
import validators
import time

from uuid import UUID

import apilityio.model as model
import apilityio.common as common
import apilityio.errors as errors

_logger = logging.getLogger(__name__)


class Client(object):
    """Create the web service client to access the API. This class implements all the logic of the client to connect to the API services of Apility.io.

    Keyword Arguments:
      - ``api_key``: A string containing your Apility.io API Key.
      - ``protocol``: A string containing the protocol to connect to the API. Protocols allowed HTTP and HTTPS. Default protocol is HTTPS.
      - ``host``: A string containing the FQDN of the host runnign the API.

    Raises:
      :func:`~apilityio.errors.ApilityioValueError`:: If the provided arguments cannot connect to the API Service.
    """

    def __init__(self, api_key=None, protocol=common.HTTPS_PROTOCOL, host=common.DEFAULT_HOST):
        self._api_key = api_key
        if api_key is not None and not self._ValidateUUID(api_key):
            raise errors.ApilityioValueError(
                'Not a valid API KEY. Is this a UUID?')

        if protocol not in [common.HTTPS_PROTOCOL, common.HTTP_PROTOCOL]:
            raise errors.ApilityioValueError('Not a valid Protocol.')

        self._protocol = protocol
        self._host = host

    def _ValidateUUID(self, uuid_string):
        """
        Validate that a UUID string is in
        fact a valid uuid.

        Happily, the uuid module does the actual
        checking for us.

        It is vital that the 'version' kwarg be passed
        to the UUID() call, otherwise any 32-character
        hex string is considered valid.
        """

        try:
            UUID(uuid_string, version=4)
        except ValueError:
            # If it's a value error, then the string
            # is not a valid hex code for a UUID.
            return False

        return True

    def _GetURL(self):
        return '%s://%s' % (self._protocol, self._host)

    def _ValidateIP(self, ip_address):
        """Validate if this is well formated ip address
        """
        try:
            ipaddress.ip_address(ip_address)
        except Exception:
            raise errors.ApilityioValueError('Not a valid IP address.')

    def _ValidateIPList(self, ip_addresses):
        """Validate if all the elements are well formated ip address list
        """
        if ip_addresses is None or len(ip_addresses) == 0:
            raise errors.ApilityioValueError('Empty list.')
        try:
            for ip_address in ip_addresses:
                ipaddress.ip_address(ip_address)
        except Exception:
            raise errors.ApilityioValueError('Not a valid IP address')

    def _ValidateDomain(self, domain):
        """Validate if this is well formated domain
        """
        try:
            return validators.domain(domain)
        except Exception:
            raise errors.ApilityioValueError('Not a valid Domain.')

    def _ValidateDomainList(self, domains):
        """Validate if all the elements are well formed domains list
        """
        if domains is None or len(domains) == 0:
            raise errors.ApilityioValueError('Empty list.')
        try:
            for domain in domains:
                validators.domain(domain)
        except Exception:
            raise errors.ApilityioValueError('Not a valid Domain.')

    def _ValidateEmail(self, email):
        """Validate if this is well formated email
        """
        try:
            return validators.email(email)
        except Exception:
            raise errors.ApilityioValueError('Not a valid Email.')

    def _ValidateEmailList(self, emails):
        """Validate if all the elements are well formed emails list
        """
        if emails is None or len(emails) == 0:
            raise errors.ApilityioValueError('Empty list.')
        try:
            for email in emails:
                validators.email(email)
        except Exception:
            raise errors.ApilityioValueError('Not a valid Email.')

    def _ValidateASNum(self, asnum):
        """Validate if this is well formated asnum
        """
        try:
            asnumber = int(asnum)
            if asnumber <= 0:
                raise errors.ApilityioValueError(
                    'Not a valid ASNUM. Negative number.')
            return True
        except Exception:
            raise errors.ApilityioValueError(
                'Not a valid ASNUM. It is a string.')

    def _ValidateASNumList(self, as_numbers):
        """Validate if all the elements are well formed AS number list
        """
        if as_numbers is None or len(as_numbers) == 0:
            raise errors.ApilityioValueError('Empty list.')
        try:
            for as_number in as_numbers:
                asnum = int(as_number)
                if asnum <= 0:
                    raise errors.ApilityioValueError(
                        'Not a valid ASNUM. Negative number.')
        except Exception:
            raise errors.ApilityioValueError(
                'Not a valid ASNUM. It is a string.')

    def _ValidateTimestampSeconds(self, timestamp):
        """Validate if this is well formated timestamp
        """
        try:
            timestamp = int(timestamp)
            if timestamp <= 0:
                raise errors.ApilityioValueError(
                    'Not a valid Timestamp. Negative number.')
            return True
        except Exception:
            raise errors.ApilityioValueError(
                'Not a valid Timestamp. It is a string.')

    def _ValidatePage(self, page):
        """Validate if page is in the correct range
        """
        try:
            page = int(page)
            if page < 1:
                raise errors.ApilityioValueError(
                    'Not a valid Page number. Must be bigger than 0.')
            return True
        except Exception:
            raise errors.ApilityioValueError(
                'Not a valid Page number. It is a string.')

    def _ValidateItems(self, items):
        """Validate if items is in the correct range
        """
        try:
            items = int(items)
            if items < 5:
                raise errors.ApilityioValueError(
                    'Not a valid Items number. Must be bigger than 4.')
            return True
        except Exception:
            raise errors.ApilityioValueError(
                'Not a valid Items number. It is a string.')

    def _ValidateTTL(self, ttl):
        """Validate if the TTL  is in the correct range
        """
        try:
            ttl = int(ttl)
            if ttl < 0:
                raise errors.ApilityioValueError(
                    'Not a valid TTL number. Must be bigger than -1.')
            return True
        except Exception:
            raise errors.ApilityioValueError(
                'Not a valid Items number. It is a string.')

    def _ValidateCountry(self, country):
        """Validate if the country is valid 3166-1
        """
        try:
            if len(country) != 2:
                raise errors.ApilityioValueError(
                    'Must be a two chars ISO 3166-1 code.')
            if country.upper() not in common.COUNTRY_LIST:
                raise errors.ApilityioValueError(
                    'Cannot find the country. Check the two chars code.')
            return True
        except Exception:
            raise errors.ApilityioValueError('Not a valid Country.')

    def _ValidateContinent(self, continent):
        """Validate if the continent is valid two code value
        """
        try:
            if len(continent) != 2:
                raise errors.ApilityioValueError(
                    'Must be a two chars continent code: EU, AS, NA, AF, AN, SA, OC')
            if continent.upper() not in common.CONTINENT_LIST:
                raise errors.ApilityioValueError(
                    'Cannot find the continent. Check the two chars code.')
            return True
        except Exception:
            raise errors.ApilityioValueError('Not a valid Continent.')

    def GetConnectionData(self):
        """Return connection data used, the API KEY (if any), the protocol (http or https) and the hostname (api.apility.net by default).

        Returns:
          - ``api_key``: a string representing the Apility.io API KEY
          - ``protocol``: a string representing the connection protocol http or https.
          - ``host``: a string representing the FQDN where the Apility.io API is listening.
        """
        return self._api_key, self._protocol, self._host

    def CheckIP(self, ip_address):
        """Check the IP address belongs to any list of the blacklist databases of Apility.io. It also returns the blacklists where the IP address was found.

        Arguments:
          - ``ip_address``: A string containing the IP address to check.

        Returns:
          - :func:`~apilityio.model.BadIPResponse`: an object containing the HTTP status code response, the error (if any) and the list of blacklists where the IP address was found. A 404 HTTP response means that the IP address was not found in any blacklists. A 200 HTTP response means that the IP address was found in one or more blacklists and the developer can check the lists in the blacklists.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not valid IP address.
        """
        self._ValidateIP(ip_address)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'badip', ip_address)

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('BadIp Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.BadIPResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.not_found:
            dto = model.BadIPResponse(status_code=response.status_code)
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            blacklists = json_dump['response']
            dto = model.BadIPResponse(blacklists=blacklists, json=json_dump)
            return dto

        return model.BadIPResponse(status_code=response.status_code, error=response.text)

    def CheckBatchIP(self, ip_addresses):
        """Check if a list of IP addresses belong to any list of the blacklist databases of Apility.io. It also returns the blacklists where the IP addresses were found.

        Arguments:
          - ``ip_addresses``: A list composed of strings containing the IP addresses to check.

        Returns:
          - :func:`~apilityio.model.BadBatchIPResponse`: an object containing the HTTP status code response, the error (if any) and the list of blacklists where the IP addresses were found. For each IP address there is a list containing the blacklists where the IP was found. If the IP was not found in any blackllist then the list is empty.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not valid list of IP addresses.
        """

        self._ValidateIPList(ip_addresses)

        endpoint = '%s/%s/%s' % (self._GetURL(),
                                 'badip_batch', ','.join(ip_addresses))

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('BadIp Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.BadBatchIPResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            ipblacklists = json_dump['response']
            ipblacklists_set = set()
            for ipblacklist_pair in ipblacklists:
                ipblacklists_set.add(model.IPBlacklist(
                    ipblacklist_pair['ip'], ipblacklist_pair['blacklists']))
            dto = model.BadBatchIPResponse(
                ipblacklists_set=ipblacklists_set, json=json_dump)
            return dto

        return model.BadBatchIPResponse(status_code=response.status_code, error=response.text)

    def GetGeoIP(self, ip_address):
        """Get the IP address geo-location information.

        Arguments:
          - ``ip_address``: A string containing the IP address to geo-locate.

        Returns:
          - :func:`~apilityio.model.GeoIPResponse`: an object containing the HTTP status code response, the error (if any) and the object containing the geo location properties of the IP address.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not valid IP address.
        """
        self._ValidateIP(ip_address)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'geoip', ip_address)

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('GeoIp Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.GeoIPResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            geoip = json_dump['ip']
            dto = model.GeoIPResponse(geoip=geoip, json=json_dump)
            return dto

        return model.GeoIPResponse(status_code=response.status_code, error=response.text)

    def GetGeoBatchIP(self, ip_addresses):
        """Get the gelocation information of a list of ip addresses passed as argument.

        Arguments:
          - ``ip_addresses``: A list of strings containing the IP addresses to geo-locate.

        Returns:
          - :func:`~apilityio.model.GeoBatchIPResponse`: an object containing the HTTP status code response, the error (if any) and a list of objects containing the geo location properties of the IP addresses.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not a list of valid IP addresses.
        """

        self._ValidateIPList(ip_addresses)

        endpoint = '%s/%s/%s' % (self._GetURL(),
                                 'geoip_batch', ','.join(ip_addresses))

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('GeoIP Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.GeoBatchIPResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            geolocated_ip_addresses = json_dump['response']
            geolocated_ip_list = []
            for geolocated_ip in geolocated_ip_addresses:
                geolocated_ip_list.append(model.IPGeodata(
                    geolocated_ip['ip'], model.GeoIP(geolocated_ip['geoip'])))
            dto = model.GeoBatchIPResponse(
                geolocated_ip_list=geolocated_ip_list, json=json_dump)
            return dto

        return model.GeoBatchIPResponse(status_code=response.status_code, error=response.text)

    def CheckDomain(self, domain):
        """Check the Domain and its MX and NS records belong to any list of the blacklist databases of Apility.io. It returns the scoring and blacklists where the Domain info was found.

        Arguments:
          - ``domain``: A string containing the domain to check.

        Returns:
          - :func:`~apilityio.model.BadDomainResponse`: an object containing the HTTP status code response, the error (if any) and the scoring and lists of blacklists where the Domain, MX and NS records were found. A 200 HTTP response means that the Domain, MX or NS records were found in one or more blacklists and the developer can check the scoring and the blacklists.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not valid FQDN.
        """

        self._ValidateDomain(domain)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'baddomain', domain)

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('Baddomain Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.BadDomainResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            baddomain_response = json_dump['response']
            dto = model.BadDomainResponse(
                domain_data=baddomain_response, json=json_dump)
            return dto

        return model.BadDomainResponse(status_code=response.status_code, error=response.text)

    def CheckBatchDomain(self, domains):
        """Check if a list of Domain and its MX and NS records belong to any list of the blacklist databases of Apility.io. It returns a list of the scoring and blacklists where the Domains info were found.

        Arguments:
          - ``domains``: A list composed of strings containing the domains to check.

        Returns:
          - :func:`~apilityio.model.BadBatchDomainResponse`: an object containing the HTTP status code response, the error (if any) and the list of blacklists where the IP addresses were found. Also the list of domains pairing the scoring and lists of blacklists where the Domain, MX and NS records were found.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not valid list of domains.
        """

        self._ValidateDomainList(domains)

        endpoint = '%s/%s/%s' % (self._GetURL(),
                                 'baddomain_batch', ','.join(domains))

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('BadDomain Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.BadBatchDomainResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            domains = json_dump['response']
            domain_list = []
            for domain in domains:
                domain_list.append(model.DomainScored(
                    domain['domain'], model.BadDomain(domain['scoring'])))
            dto = model.BadBatchDomainResponse(
                domain_scoring_list=domain_list, json=json_dump)
            return dto

        return model.BadBatchDomainResponse(status_code=response.status_code, error=response.text)

    def CheckEmail(self, email):
        """Check the Email including all tests performed to the Domain plus a full SMTP test on the remote server. It returns the global scoring of the Email and each scoring per test performed.

        Arguments:
          - ``email``: A string containing the email to check.

        Returns:
          - :func:`~apilityio.model.BadEmailResponse`: an object containing the HTTP status code response, the error (if any) and the scoring and lists of blacklists where the Emal, SMTP server, MX and NS records were found. A 200 HTTP response means that the Domain, SMTP Server, MX or NS records were found in one or more blacklists and the developer can check the scoring and the blacklists.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not valid Email.
        """
        self._ValidateEmail(email)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'bademail', email)

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('Bademail Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.BadEmailResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            bademail_response = json_dump['response']
            dto = model.BadEmailResponse(
                email_data=bademail_response, json=json_dump)
            return dto

        return model.BadEmailResponse(status_code=response.status_code, error=response.text)

    def CheckBatchEmail(self, emails):
        """Check if a list of Emails including all tests performed to the Domain plus a full SMTP test on the remote server. It returns the global scoring of each Email and each scoring per test performed.

        Arguments:
          - ``emails``: A list composed of strings containing the emails to check.

        Returns:
          - :func:`~apilityio.model.BadBatchEmailResponse`: an object containing the HTTP status code response, the error (if any). Also the list of emails pairing the scoring and lists of blacklists where the Emails, tests and domains and MX and NS records were found.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not valid list of emails.
        """

        self._ValidateEmailList(emails)

        endpoint = '%s/%s/%s' % (self._GetURL(),
                                 'bademail_batch', ','.join(emails))

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('BadEmails Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.BadBatchEmailResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            emails = json_dump['response']
            email_list = []
            for email in emails:
                email_list.append(model.EmailScored(
                    email['email'], model.BadEmail(email['scoring'])))
            dto = model.BadBatchEmailResponse(
                email_scoring_list=email_list, json=json_dump)
            return dto

        return model.BadBatchEmailResponse(status_code=response.status_code, error=response.text)

    def GetASbyIP(self, ip_address):
        """Get the Autonomous System information of a given IP address.

        Arguments:
          - ``ip_address``: A string containing the IP address to obtain information of its Autonomous System.

        Returns:
          - :func:`~apilityio.model.ASResponse`: an object containing the HTTP status code response, the error (if any) and the object containing the Autonomous System properties of the IP address.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not valid IP address.
        """
        self._ValidateIP(ip_address)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'as/ip', ip_address)

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('AsIP Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.ASResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            asystem = json_dump['as']
            dto = model.ASResponse(asystem=asystem, json=json_dump)
            return dto

        return model.ASResponse(status_code=response.status_code, error=response.text)

    def GetASbyNum(self, asnum):
        """Get the Autonomous System information by its number (ASN).

        Arguments:
          - ``asnum``: An integer containing the ASN to obtain information of.

        Returns:
          - :func:`~apilityio.model.ASResponse`: an object containing the HTTP status code response, the error (if any) and the object containing the Autonomous System properties.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not AS number.
        """
        self._ValidateASNum(asnum)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'as/num', int(asnum))

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('AsNum Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.ASResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            asystem = json_dump['as']
            dto = model.ASResponse(asystem=asystem, json=json_dump)
            return dto

        return model.ASResponse(status_code=response.status_code, error=response.text)

    def GetASBatchByIP(self, ip_addresses):
        """Get the Autonomous System information of a list of ip addresses passed as argument.

        Arguments:
          - ``ip_addresses``: A list of strings containing the IP addresses to get AS data.

        Returns:
          - :func:`~apilityio.model.ASBatchIPResponse`: an object containing the HTTP status code response, the error (if any) and a list of objects containing the Autonomous System properties of the IP addresses.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not a list of valid IP addresses.
        """

        self._ValidateIPList(ip_addresses)

        endpoint = '%s/%s/%s' % (self._GetURL(),
                                 'as_batch/ip', ','.join(ip_addresses))

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('ASbyIP Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.ASBatchIPResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            asystem_ip_addresses = json_dump['response']
            asystem_ip_list = []
            for asystem_ip in asystem_ip_addresses:
                asystem_ip_list.append(model.IPASystem(
                    asystem_ip['ip'], model.ASystem(asystem_ip['as'])))
            dto = model.ASBatchIPResponse(
                asystem_ip_list=asystem_ip_list, json=json_dump)
            return dto

        return model.ASBatchIPResponse(status_code=response.status_code, error=response.text)

    def GetASBatchByNum(self, as_numbers):
        """Get the Autonomous System information of a list of AS numbers passed as argument.

        Arguments:
          - ``as_numbers``: A list of integers containing the AS numbers to get AS data.

        Returns:
          - :func:`~apilityio.model.ASBatchIPResponse`: an object containing the HTTP status code response, the error (if any) and a list of objects containing the Autonomous System properties of the AS numbers.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not a list of valid AS numbers.
        """

        self._ValidateASNumList(as_numbers)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'as_batch/num',
                                 ','.join([str(x) for x in as_numbers]))

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('ASbyNum Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.ASBatchNumResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            asystem_numbers = json_dump['response']
            asystem_num_list = []
            for asystem_num in asystem_numbers:
                asystem_num_list.append(model.ASNASystem(
                    asystem_num['asn'], model.ASystem(asystem_num['as'])))
            dto = model.ASBatchNumResponse(
                asystem_num_list=asystem_num_list, json=json_dump)
            return dto

        return model.ASBatchNumResponse(status_code=response.status_code, error=response.text)

    def GetWhoisIP(self, ip_address):
        """Get the WHOIS information of a given IP address.

        Arguments:
          - ``ip_address``: A string containing the IP address to obtain information of its WHOIS database.

        Returns:
          - :func:`~apilityio.model.WhoisIPResponse`: an object containing the HTTP status code response, the error (if any) and the object containing the WHOIS properties of the IP address.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not valid IP address.
        """

        self._ValidateIP(ip_address)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'whois/ip', ip_address)

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('WHOISIP Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.WhoisIPResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            whois = json_dump['whois']
            dto = model.WhoisIPResponse(whois=whois, json=json_dump)
            return dto

        return model.WhoisIPResponse(status_code=response.status_code, error=response.text)

    def GetHistoryIP(self, ip_address, timestamp=None, items=5, page=1):
        """Get the list of transactions of a given IP address in our database. For experts who wish to know the historical activity of the given IP address in our database.

        Arguments:
          - ``ip_address``: A string containing the IP address to obtain the historical information.
          - ``page``: (Optional) An integer starting with 1 to paginate the results of the query.
          - ``items``: (Optional) An integer with the number of items to return per page. From five to two hundred as maximum.
          - ``timestamp``: (Optional) An integer as UNIX time in seconds to limit the search. The search will be filtered by values less or equal than ``timestamp``.

        Returns:
          - :func:`~apilityio.model.HistoryIPResponse`: an object containing the HTTP status code response, the error (if any) and the object containing all historical information.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided arguments are not a valid IP address, page, items or timestamp.
        """

        self._ValidateIP(ip_address)
        if timestamp:
            self._ValidateTimestampSeconds(timestamp)
        else:
            timestamp = int(time.time())
        self._ValidatePage(page)
        self._ValidateItems(items)

        endpoint = '%s/%s/%s?timestamp=%s&page=%s&items=%s' % (
            self._GetURL(), 'metadata/changes/ip', ip_address, timestamp, page, items)

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('HISTORYIP Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.unauthorized:
            dto = model.HistoryIPResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            history = json_dump['changes_ip']
            dto = model.HistoryIPResponse(history=history, json=json_dump)
            return dto

        return model.HistoryIPResponse(status_code=response.status_code, error=response.text)

    def GetHistoryDomain(self, domain, timestamp=None, items=5, page=1):
        """Get the list of transactions of a given Domain in our database. For experts who wish to know the historical activity of the given domain in our database.

        Arguments:
          - ``domain``: A string containing the FQDN to obtain the historical information.
          - ``page``: (Optional) An integer starting with 1 to paginate the results of the query.
          - ``items``: (Optional) An integer with the number of items to return per page. From five to two hundred as maximum.
          - ``timestamp``: (Optional) An integer as UNIX time in seconds to limit the search. The search will be filtered by values less or equal than ``timestamp``.

        Returns:
          - :func:`~apilityio.model.HistoryDomainResponse`: an object containing the HTTP status code response, the error (if any) and the object containing all historical information.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided arguments are not a valid FQDN, page, items or timestamp.
        """

        self._ValidateDomain(domain)
        if timestamp:
            self._ValidateTimestampSeconds(timestamp)
        else:
            timestamp = int(time.time())
        self._ValidatePage(page)
        self._ValidateItems(items)

        endpoint = '%s/%s/%s?timestamp=%s&page=%s&items=%s' % (
            self._GetURL(), 'metadata/changes/domain', domain, timestamp, page, items)

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('HISTORYDOMAIN Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.unauthorized:
            dto = model.HistoryDomainResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            history = json_dump['changes_domain']
            dto = model.HistoryDomainResponse(history=history, json=json_dump)
            return dto

        return model.HistoryDomainResponse(status_code=response.status_code, error=response.text)

    def GetHistoryEmail(self, email, timestamp=None, items=5, page=1):
        """Get the list of transactions of a given Email in our database. For experts who wish to know the historical activity of the given Email in our database.

        Arguments:
          - ``email``: A string containing the Email to obtain the historical information.
          - ``page``: (Optional) An integer starting with 1 to paginate the results of the query.
          - ``items``: (Optional) An integer with the number of items to return per page. From five to two hundred as maximum.
          - ``timestamp``: (Optional) An integer as UNIX time in seconds to limit the search. The search will be filtered by values less or equal than ``timestamp``.

        Returns:
          - :func:`~apilityio.model.HistoryEmailResponse`: an object containing the HTTP status code response, the error (if any) and the object containing all historical information.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided arguments are not a valid Email, page, items or timestamp.
        """

        self._ValidateEmail(email)
        if timestamp:
            self._ValidateTimestampSeconds(timestamp)
        else:
            timestamp = int(time.time())
        self._ValidatePage(page)
        self._ValidateItems(items)

        endpoint = '%s/%s/%s?timestamp=%s&page=%s&items=%s' % (
            self._GetURL(), 'metadata/changes/email', email, timestamp, page, items)

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('HISTORYEMAIL Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.unauthorized:
            dto = model.HistoryEmailResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            history = json_dump['changes_email']
            dto = model.HistoryEmailResponse(history=history, json=json_dump)
            return dto

        return model.HistoryEmailResponse(status_code=response.status_code, error=response.text)

    def GetQuarantineIP(self):
        """Get the list of IP addresses in the quarantine. Quarantine is a private exclusion lists based on user IP address properties.

        Returns:
          - :func:`~apilityio.model.QuarantineIPResponse`: an object containing the HTTP status code response, the error (if any) and the object containing all the IP addresses in the quarantine.

        """

        endpoint = '%s/%s' % (self._GetURL(), 'quarantine/ip')

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('QUARANTINEIP GET Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.unauthorized:
            dto = model.QuarantineIPResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            quarantine = json_dump['quarantined']
            dto = model.QuarantineIPResponse(quarantine=quarantine, json=json_dump)
            return dto

        return model.QuarantineIPResponse(status_code=response.status_code, error=response.text)

    def GetQuarantineCountry(self):
        """Get the list of countries in the quarantine. Quarantine is a private exclusion lists based on user IP address properties. In this case, the country the IP belongs to.

        Returns:
          - :func:`~apilityio.model.QuarantineCountryResponse`: an object containing the HTTP status code response, the error (if any) and the object containing all the countries in the quarantine.

        """

        endpoint = '%s/%s' % (self._GetURL(), 'quarantine/country')

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('QUARANTINECOUNTRY GET Endpoint: %s. Response: %s:%s' % (
            endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.unauthorized:
            dto = model.QuarantineCountryResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            quarantine = json_dump['quarantined']
            dto = model.QuarantineCountryResponse(quarantine=quarantine, json=json_dump)
            return dto

        return model.QuarantineCountryResponse(status_code=response.status_code, error=response.text)

    def GetQuarantineContinent(self):
        """Get the list of continents in the quarantine. Quarantine is a private exclusion lists based on user IP address properties. In this case, the continent the IP belongs to.

        Returns:
          - :func:`~apilityio.model.QuarantineContinentResponse`: an object containing the HTTP status code response, the error (if any) and the object containing all the continents in the quarantine.

        """

        endpoint = '%s/%s' % (self._GetURL(), 'quarantine/continent')

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('QUARANTINECONTINENT GET Endpoint: %s. Response: %s:%s' % (
            endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.unauthorized:
            dto = model.QuarantineContinentResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            quarantine = json_dump['quarantined']
            dto = model.QuarantineContinentResponse(quarantine=quarantine, json=json_dump)
            return dto

        return model.QuarantineContinentResponse(status_code=response.status_code, error=response.text)

    def GetQuarantineAS(self):
        """Get the list of Autonomous Systems in the quarantine. Quarantine is a private exclusion lists based on user IP address properties. In this case, the AS the IP belongs to.

        Returns:
          - :func:`~apilityio.model.QuarantineASResponse`: an object containing the HTTP status code response, the error (if any) and the object containing all the AS in the quarantine.

        """

        endpoint = '%s/%s' % (self._GetURL(), 'quarantine/as')

        response = requests.request("GET", endpoint, headers={
                                    'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('QUARANTINEAS GET Endpoint: %s. Response: %s:%s' %
                      (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.unauthorized:
            dto = model.QuarantineASResponse(
                status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            json_dump = response.json()
            quarantine = json_dump['quarantined']
            dto = model.QuarantineASResponse(quarantine=quarantine, json=json_dump)
            return dto

        return model.QuarantineASResponse(status_code=response.status_code, error=response.text)

    def _AddQuarantineObject(self, object_type, object_value, ttl, object_uri_type=None):
        payload = {"%s" % object_type: object_value, "ttl": ttl}
        if object_uri_type is not None:
            object_type = object_uri_type
        endpoint = '%s/%s' % (self._GetURL(), 'quarantine/%s' % object_type)
        _logger.debug(payload)
        response = requests.request("POST", endpoint, json=payload,
                                    headers={'X-Auth-Token': self._api_key, 'Accept': 'application/json'})
        _logger.debug('QUARANTINE%s POST Endpoint: %s. Response: %s:%s' % (
            object_type.upper(), endpoint, response.status_code, response.text))
        if response.status_code == requests.codes.unauthorized:
            dto = model.Response(
                status_code=response.status_code, error='Bad Request.')
            return dto
        if response.status_code == requests.codes.ok:
            dto = model.Response(status_code=response.status_code, error='OK.')
            return dto
        return model.Response(status_code=response.status_code, error=response.text)

    def AddQuarantineIP(self, ip_address, ttl=3600):
        """Add an IP address for  a given time to live in the quarantine list.

        Arguments:
          - ``ip_address``: A string containing a valid IP address to include in the QUARANTINE-IP list.
          - ``ttl``: (Optional) An integer as in seconds to limit the time to live the IP address in the list. By default is 3600 seconds. Zero value if the IP address will never expire in the list.

        Returns:
          - :func:`~apilityio.model.Response`: an object containing the HTTP status code response and the error (if any).

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided arguments are not a valid IP address or TTL value.
        """

        self._ValidateIP(ip_address)
        self._ValidateTTL(ttl)
        object_type = 'ip'

        return self._AddQuarantineObject(object_type, ip_address, ttl)

    def AddQuarantineCountry(self, country, ttl=3600):
        """Add a country for a given time to live in the quarantine list.

        Arguments:
          - ``country``: A string containing a valid ISO-3166-1 country  to include in the QUARANTINE-IP list.
          - ``ttl``: (Optional) An integer as in seconds to limit the time to live the country in the list. By default is 3600 seconds. Zero value if the country will never expire in the list.

        Returns:
          - :func:`~apilityio.model.Response`: an object containing the HTTP status code response and the error (if any).

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided arguments are not a valid country code or TTL value.
        """

        self._ValidateCountry(country)
        self._ValidateTTL(ttl)
        object_type = 'country'

        return self._AddQuarantineObject(object_type, country, ttl)

    def AddQuarantineContinent(self, continent, ttl=3600):
        """Add a continent for a given time to live in the quarantine list.

        Arguments:
          - ``continent``: A string containing a valid continent  to include in the QUARANTINE-CONTINENT list. Valid codes are EU, AS, NA, AF, AN, SA, OC.
          - ``ttl``: (Optional) An integer as in seconds to limit the time to live the continent in the list. By default is 3600 seconds. Zero value if the continent will never expire in the list.

        Returns:
          - :func:`~apilityio.model.Response`: an object containing the HTTP status code response and the error (if any).

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided arguments are not a valid continent code or TTL value.
        """

        self._ValidateContinent(continent)
        self._ValidateTTL(ttl)
        object_type = 'continent'

        return self._AddQuarantineObject(object_type, continent, ttl)

    def AddQuarantineAS(self, asnum, ttl=3600):
        """Add an Autonomous System number for a given time to live in the quarantine list.

        Arguments:
          - ``asnum``: An integer containing a valid Autonomous System Number (ASN  to include in the QUARANTINE-AS list.
          - ``ttl``: (Optional) An integer as in seconds to limit the time to live the AS in the list. By default is 3600 seconds. Zero value if the AS will never expire in the list.

        Returns:
          - :func:`~apilityio.model.Response`: an object containing the HTTP status code response and the error (if any).

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided arguments are not a valid ASN or TTL value.
        """

        self._ValidateASNum(asnum)
        self._ValidateTTL(ttl)
        object_type = 'asn'

        return self._AddQuarantineObject(object_type, asnum, ttl, object_uri_type='as')

    def _DeleteQuarantineObject(self, object_type, object_value):
        endpoint = '%s/%s/%s' % (self._GetURL(),
                                 'quarantine/%s' % object_type, object_value)
        response = requests.request("DELETE", endpoint, headers={
                                    'X-Auth-Token': self._api_key})
        _logger.debug('QUARANTINE%s DELETE Endpoint: %s. Response: %s:%s' % (
            object_type.upper(), endpoint, response.status_code, response.text))
        if response.status_code == requests.codes.unauthorized:
            dto = model.Response(
                status_code=response.status_code, error='Bad Request.')
            return dto
        if response.status_code == requests.codes.ok:
            dto = model.Response(status_code=response.status_code, error='OK.')
            return dto
        return model.Response(status_code=response.status_code, error=response.text)

    def DeleteQuarantineIP(self, ip_address):
        """Delete an IP address from the quarantine list.

        Arguments:
          - ``ip_address``: A string containing a valid IP address to remove of the QUARANTINE-IP list.

        Returns:
          - :func:`~apilityio.model.Response`: an object containing the HTTP status code response and the error (if any). If the IP address does not exists, it will also return a 200 status code.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not a valid IP address.
        """

        self._ValidateIP(ip_address)
        object_type = 'ip'

        return self._DeleteQuarantineObject(object_type, ip_address)

    def DeleteQuarantineCountry(self, country):
        """Delete a country from the quarantine list.

        Arguments:
          - ``country``: A string containing a valid ISO-3166-1 country code to remove of the QUARANTINE-COUNTRY list.

        Returns:
          - :func:`~apilityio.model.Response`: an object containing the HTTP status code response and the error (if any). If the country does not exists, it will also return a 200 status code.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not a valid country code.
        """

        self._ValidateCountry(country)
        object_type = 'country'

        return self._DeleteQuarantineObject(object_type, country)

    def DeleteQuarantineContinent(self, continent):
        """Delete a continent from the quarantine list.

        Arguments:
          - ``continent``: A string containing a valid continent code to remove of the QUARANTINE-CONTINENT list. Valid codes are EU, AS, NA, AF, AN, SA, OC.

        Returns:
          - :func:`~apilityio.model.Response`: an object containing the HTTP status code response and the error (if any). If the continent does not exists, it will also return a 200 status code.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not a valid continent code.
        """

        self._ValidateContinent(continent)
        object_type = 'continent'

        return self._DeleteQuarantineObject(object_type, continent)

    def DeleteQuarantineAS(self, asn):
        """Delete an Autonomous System from the quarantine list.

        Arguments:
          - ``asn``: A string containing a valid Autonomous System Number (ASN) to remove of the QUARANTINE-AS list.

        Returns:
          - :func:`~apilityio.model.Response`: an object containing the HTTP status code response and the error (if any). If the ASN does not exists, it will also return a 200 status code.

        Raises:
          - :func:`~apilityio.errors.ApilityioValueError`: If the provided argument is not a valid ASN.
        """

        self._ValidateASNum(asn)
        object_type = 'as'

        return self._DeleteQuarantineObject(object_type, asn)
