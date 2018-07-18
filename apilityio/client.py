"""
Copyright 2017-2018 CAPITAL LAB OÜ

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
import ipaddress
import requests
import logging
import validators
import datetime

from uuid import UUID

import apilityio.model as model
import apilityio.common as common
import apilityio.errors as errors

_logger = logging.getLogger(__name__)

def ValidateUUID(uuid_string):

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
        val = UUID(uuid_string, version=4)
    except ValueError:
        # If it's a value error, then the string
        # is not a valid hex code for a UUID.
        return False

    return True

class Client(object):
    """Create web service clients to access the API.
    """

    def __init__(self, api_key = None, protocol = common.HTTPS_PROTOCOL ,host = common.DEFAULT_HOST):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          api_key: A string containing your Apility.io API Key.
          protocol: A string containing the protocol to connect to the API. Protocols allowed HTTP and HTTPS.
              Default protocol is HTTPS.
          host: A string containing the FQDN of the host runnign the API.

        Raises:
          ApilityioConnectionError: If the provided arguments cannot connect to the API Service.
        """
        self._api_key = api_key
        if api_key is not None and not ValidateUUID(api_key):
            raise errors.ApilityioValueError('Not a valid API KEY. Is this a UUID?')

        if protocol not in [common.HTTPS_PROTOCOL, common.HTTP_PROTOCOL]:
            raise errors.ApilityioValueError('Not a valid Protocol.')

        self._protocol = protocol
        self._host = host

    def _GetURL(self):
        return '%s://%s' % (self._protocol, self._host)

    def _ValidateIP(self, ip_address):
        """Validate if this is well formated ip address
        """
        try:
            ipaddress.ip_address(ip_address)
        except Exception as e:
            raise errors.ApilityioValueError('Not a valid IP address.')

    def _ValidateIPList(self, ip_addresses):
        """Validate if all the elements are well formated ip address list
        """
        if ip_addresses is None or len(ip_addresses) == 0:
            raise errors.ApilityioValueError('Empty list.')
        try:
            for ip_address in ip_addresses:
                ipaddress.ip_address(ip_address)
        except Exception as e:
            raise errors.ApilityioValueError('Not a valid IP address')

    def _ValidateDomain(self, domain):
        """Validate if this is well formated domain
        """
        try:
            return validators.domain(domain)
        except Exception as e:
            raise errors.ApilityioValueError('Not a valid Domain.')

    def _ValidateDomainList(self, domains):
        """Validate if all the elements are well formed domains list
        """
        if domains is None or len(domains) == 0:
            raise errors.ApilityioValueError('Empty list.')
        try:
            for domain in domains:
                validators.domain(domain)
        except Exception as e:
            raise errors.ApilityioValueError('Not a valid Domain.')

    def _ValidateEmail(self, email):
        """Validate if this is well formated email
        """
        try:
            return validators.email(email)
        except Exception as e:
            raise errors.ApilityioValueError('Not a valid Email.')

    def _ValidateEmailList(self, emails):
        """Validate if all the elements are well formed emails list
        """
        if emails is None or len(emails) == 0:
            raise errors.ApilityioValueError('Empty list.')
        try:
            for email in emails:
                validators.email(email)
        except Exception as e:
            raise errors.ApilityioValueError('Not a valid Email.')

    def _ValidateASNum(self, asnum):
        """Validate if this is well formated asnum
        """
        try:
            asnumber = int(asnum)
            if asnum<=0:
                raise errors.ApilityioValueError('Not a valid ASNUM. Negative number.')
            return True
        except Exception as e:
            raise errors.ApilityioValueError('Not a valid ASNUM. It is a string.')

    def _ValidateASNumList(self, as_numbers):
        """Validate if all the elements are well formed AS number list
        """
        if as_numbers is None or len(as_numbers) == 0:
            raise errors.ApilityioValueError('Empty list.')
        try:
            for as_number in as_numbers:
                asnum = int(as_number)
                if asnum<=0:
                    raise errors.ApilityioValueError('Not a valid ASNUM. Negative number.')
        except Exception as e:
            raise errors.ApilityioValueError('Not a valid ASNUM. It is a string.')

    def _ValidateTimestampSeconds(self, timestamp):
        """Validate if this is well formated timestamp
        """
        try:
            timestamp = int(timestamp)
            if timestamp<=0:
                raise errors.ApilityioValueError('Not a valid Timestamp. Negative number.')
            return True
        except Exception as e:
            raise errors.ApilityioValueError('Not a valid Timestamp. It is a string.')

    def _ValidatePage(self, page):
        """Validate if page is in the correct range
        """
        try:
            page = int(page)
            if page<1:
                raise errors.ApilityioValueError('Not a valid Page number. Must be bigger than 0.')
            return True
        except Exception as e:
            raise errors.ApilityioValueError('Not a valid Page number. It is a string.')

    def _ValidateItems(self, items):
        """Validate if items is in the correct range
        """
        try:
            items = int(items)
            if items<5:
                raise errors.ApilityioValueError('Not a valid Items number. Must be bigger than 4.')
            return True
        except Exception as e:
            raise errors.ApilityioValueError('Not a valid Items number. It is a string.')

    def _ValidateTTL(self, ttl):
        """Validate if the TTL  is in the correct range
        """
        try:
            ttl = int(ttl)
            if ttl<0:
                raise errors.ApilityioValueError('Not a valid TTL number. Must be bigger than -1.')
            return True
        except Exception as e:
            raise errors.ApilityioValueError('Not a valid Items number. It is a string.')

    def _ValidateCountry(self, country):
        """Validate if the country is valid 3166-1
        """
        try:
            if len(country) != 2:
                raise errors.ApilityioValueError('Must be a two chars ISO 3166-1 code.')
            if country.upper() not in common.COUNTRY_LIST:
                raise errors.ApilityioValueError('Cannot find the country. Check the two chars code.')
            return True
        except Exception as e:
            raise errors.ApilityioValueError('Not a valid Country.')

    def _ValidateContinent(self, continent):
        """Validate if the continent is valid two code value
        """
        try:
            if len(continent) != 2:
                raise errors.ApilityioValueError('Must be a two chars continent code: EU, AS, NA, AF, AN, SA, OC')
            if continent.upper() not in common.CONTINENT_LIST:
                raise errors.ApilityioValueError('Cannot find the continent. Check the two chars code.')
            return True
        except Exception as e:
            raise errors.ApilityioValueError('Not a valid Continent.')

    def GetConnectionData(self):
        """Return connection data
        """
        return self._api_key, self._protocol, self._host

    def CheckIP(self, ip_address):
        """Check the IP address versus

        Arguments:
          ip_address: A string containing the IP address to check.
        """
        self._ValidateIP(ip_address)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'badip', ip_address)

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('BadIp Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.BadIPResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.not_found:
            dto = model.BadIPResponse(status_code=response.status_code)
            return dto

        if response.status_code == requests.codes.ok:
            blacklists = response.json()['response']
            dto = model.BadIPResponse(blacklists=blacklists)
            return dto

        return model.BadIPResponse(status_code=response.status_code, error=response.text)

    def CheckBatchIP(self, ip_addresses):
        """Check the Array containing the list of IP address

        Arguments:
          ip_address: An array of string containing the IP addresses to check.
        """

        self._ValidateIPList(ip_addresses)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'badip_batch', ','.join(ip_addresses))

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('BadIp Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.BadBatchIPResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            ipblacklists = response.json()['response']
            ipblacklists_set = set()
            for ipblacklist_pair in ipblacklists:
                ipblacklists_set.add(model.IPBlacklist(ipblacklist_pair['ip'], ipblacklist_pair['blacklists']))
            dto = model.BadBatchIPResponse(ipblacklists_set=ipblacklists_set)
            return dto

        return model.BadBatchIPResponse(status_code=response.status_code, error=response.text)


    def GetGeoIP(self, ip_address):
        """Get the geo location of the IP address

        Arguments:
          ip_address: A string containing the IP address to check.
        """
        self._ValidateIP(ip_address)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'geoip', ip_address)

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('GeoIp Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.GeoIPResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            geoip = response.json()['ip']
            dto = model.GeoIPResponse(geoip=geoip)
            return dto

        return model.GeoIPResponse(status_code=response.status_code, error=response.text)

    def GetGeoBatchIP(self, ip_addresses):
        """Get the Geolocation of the Array containing the list of IP address

        Arguments:
          ip_address: An array of string containing the IP addresses to check.
        """

        self._ValidateIPList(ip_addresses)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'geoip_batch', ','.join(ip_addresses))

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('GeoIP Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.GeoBatchIPResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            geolocated_ip_addresses = response.json()['response']
            geolocated_ip_list = []
            for geolocated_ip in geolocated_ip_addresses:
                geolocated_ip_list.append(model.IPGeodata(geolocated_ip['ip'], model.GeoIP(geolocated_ip['geoip'])))
            dto = model.GeoBatchIPResponse(geolocated_ip_list=geolocated_ip_list)
            return dto

        return model.GeoBatchIPResponse(status_code=response.status_code, error=response.text)

    def CheckDomain(self, domain):
        """Check the Domain score

        Arguments:
          domain: A string containing the domain to check.
        """
        self._ValidateDomain(domain)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'baddomain', domain)

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('Baddomain Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.BadDomainResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            baddomain_response = response.json()['response']
            dto = model.BadDomainResponse(domain_data=baddomain_response)
            return dto

        return model.BadDomainResponse(status_code=response.status_code, error=response.text)

    def CheckBatchDomain(self, domains):
        """Check the Array containing the list of domains

        Arguments:
          domains: An array of string containing the domains to check.
        """

        self._ValidateDomainList(domains)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'baddomain_batch', ','.join(domains))

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('BadDomain Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.BadBatchDomainResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            domains = response.json()['response']
            domain_list = []
            for domain in domains:
                domain_list.append(model.DomainScored(domain['domain'], model.BadDomain(domain['scoring'])))
            dto = model.BadBatchDomainResponse(domain_scoring_list=domain_list)
            return dto

        return model.BadBatchDomainResponse(status_code=response.status_code, error=response.text)

    def CheckEmail(self, email):
        """Check the Email score

        Arguments:
          email: A string containing the email to check.
        """
        self._ValidateEmail(email)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'bademail', email)

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('Bademail Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.BadEmailResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            bademail_response = response.json()['response']
            dto = model.BadEmailResponse(email_data=bademail_response)
            return dto

        return model.BadEmailResponse(status_code=response.status_code, error=response.text)

    def CheckBatchEmail(self, emails):
        """Check the Array containing the list of emails

        Arguments:
          emails: An array of string containing the domains to check.
        """

        self._ValidateEmailList(emails)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'bademail_batch', ','.join(emails))

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('BadEmails Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.BadBatchEmailResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            emails = response.json()['response']
            email_list = []
            for email in emails:
                email_list.append(model.EmailScored(email['email'], model.BadEmail(email['scoring'])))
            dto = model.BadBatchEmailResponse(email_scoring_list=email_list)
            return dto

        return model.BadBatchEmailResponse(status_code=response.status_code, error=response.text)

    def GetASbyIP(self, ip_address):
        """Get the Autonomous System data of the IP address given

        Arguments:
          ip_address: A string containing the IP address to check.
        """
        self._ValidateIP(ip_address)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'as/ip', ip_address)

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('AsIP Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.ASResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            asystem = response.json()['as']
            dto = model.ASResponse(asystem=asystem)
            return dto

        return model.ASResponse(status_code=response.status_code, error=response.text)

    def GetASbyNum(self, asnum):
        """Get the Autonomous System data of the asnum given

        Arguments:
          asnum: An integer containing the asnum to check.
        """
        self._ValidateASNum(asnum)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'as/num', int(asnum))

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('AsNum Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.ASResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            asystem = response.json()['as']
            dto = model.ASResponse(asystem=asystem)
            return dto

        return model.ASResponse(status_code=response.status_code, error=response.text)

    def GetASBatchByIP(self, ip_addresses):
        """Get the Autonomous system of the Array containing the list of IP addresses

        Arguments:
          ip_addresses: An array of string containing the IP addresses to check.
        """

        self._ValidateIPList(ip_addresses)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'as_batch/ip', ','.join(ip_addresses))

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('ASbyIP Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.ASBatchIPResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            asystem_ip_addresses = response.json()['response']
            asystem_ip_list = []
            for asystem_ip in asystem_ip_addresses:
                asystem_ip_list.append(model.IPASystem(asystem_ip['ip'], model.ASystem(asystem_ip['as'])))
            dto = model.ASBatchIPResponse(asystem_ip_list=asystem_ip_list)
            return dto

        return model.ASBatchIPResponse(status_code=response.status_code, error=response.text)

    def GetASBatchByNum(self, as_numbers):
        """Get the Autonomous system of the Array containing the list of as_numbers

        Arguments:
          as_numbers: An array of integers containing the AS numbers to check.
        """

        self._ValidateASNumList(as_numbers)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'as_batch/num', ','.join([str(x) for x in as_numbers]))

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('ASbyNum Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.ASBatchNumResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            asystem_numbers = response.json()['response']
            asystem_num_list = []
            for asystem_num in asystem_numbers:
                asystem_num_list.append(model.ASNASystem(asystem_num['asn'], model.ASystem(asystem_num['as'])))
            dto = model.ASBatchNumResponse(asystem_num_list=asystem_num_list)
            return dto

        return model.ASBatchNumResponse(status_code=response.status_code, error=response.text)

    def GetWhoisIP(self, ip_address):
        """Get the WHOIS information of the IP address given

        Arguments:
          ip_address: A string containing the IP address to check.
        """
        self._ValidateIP(ip_address)

        endpoint = '%s/%s/%s' % (self._GetURL(), 'whois/ip', ip_address)

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('WHOISIP Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.bad_request:
            dto = model.WhoisIPResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            whois = response.json()['whois']
            dto = model.WhoisIPResponse(whois=whois)
            return dto

        return model.WhoisIPResponse(status_code=response.status_code, error=response.text)


    def GetHistoryIP(self, ip_address, timestamp=None, items=5, page=1):
        """Get the history of the IP address given in our databases

        Arguments:
          ip_address: A string containing the IP address to check.
        """
        self._ValidateIP(ip_address)
        if timestamp:
            self._ValidateTimestampSeconds(timestamp)
        else:
            timestamp = int(datetime.datetime.utcnow().timestamp())
        self._ValidatePage(page)
        self._ValidateItems(items)

        endpoint = '%s/%s/%s?timestamp=%s&page=%s&items=%s' % (self._GetURL(), 'metadata/changes/ip', ip_address, timestamp, page, items)

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('HISTORYIP Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.unauthorized:
            dto = model.HistoryIPResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            history = response.json()['changes_ip']
            dto = model.HistoryIPResponse(history=history)
            return dto

        return model.HistoryIPResponse(status_code=response.status_code, error=response.text)

    def GetHistoryDomain(self, domain, timestamp=None, items=5, page=1):
        """Get the history of the Domain address given in our databases

        Arguments:
          domain: A string containing the domain to check.
        """
        self._ValidateDomain(domain)
        if timestamp:
            self._ValidateTimestampSeconds(timestamp)
        else:
            timestamp = int(datetime.datetime.utcnow().timestamp())
        self._ValidatePage(page)
        self._ValidateItems(items)

        endpoint = '%s/%s/%s?timestamp=%s&page=%s&items=%s' % (self._GetURL(), 'metadata/changes/domain', domain, timestamp, page, items)

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('HISTORYDOMAIN Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.unauthorized:
            dto = model.HistoryDomainResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            history = response.json()['changes_domain']
            dto = model.HistoryDomainResponse(history=history)
            return dto

        return model.HistoryDomainResponse(status_code=response.status_code, error=response.text)

    def GetHistoryEmail(self, email, timestamp=None, items=5, page=1):
        """Get the history of the Email address given in our databases

        Arguments:
          email: A string containing the Email to check.
        """
        self._ValidateEmail(email)
        if timestamp:
            self._ValidateTimestampSeconds(timestamp)
        else:
            timestamp = int(datetime.datetime.utcnow().timestamp())
        self._ValidatePage(page)
        self._ValidateItems(items)

        endpoint = '%s/%s/%s?timestamp=%s&page=%s&items=%s' % (self._GetURL(), 'metadata/changes/email', email, timestamp, page, items)

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('HISTORYEMAIL Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.unauthorized:
            dto = model.HistoryEmailResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            history = response.json()['changes_email']
            dto = model.HistoryEmailResponse(history=history)
            return dto

        return model.HistoryEmailResponse(status_code=response.status_code, error=response.text)

    def GetQuarantineIP(self):
        """Get the list of IP address quarantined

        """
        endpoint = '%s/%s' % (self._GetURL(), 'quarantine/ip')

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('QUARANTINEIP GET Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.unauthorized:
            dto = model.QuarantineIPResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            quarantine = response.json()['quarantined']
            dto = model.QuarantineIPResponse(quarantine=quarantine)
            return dto

        return model.QuarantineIPResponse(status_code=response.status_code, error=response.text)

    def GetQuarantineCountry(self):
        """Get the list of Countries quarantined

        """
        endpoint = '%s/%s' % (self._GetURL(), 'quarantine/country')

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('QUARANTINECOUNTRY GET Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.unauthorized:
            dto = model.QuarantineCountryResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            quarantine = response.json()['quarantined']
            dto = model.QuarantineCountryResponse(quarantine=quarantine)
            return dto

        return model.QuarantineCountryResponse(status_code=response.status_code, error=response.text)

    def GetQuarantineContinent(self):
        """Get the list of Continents quarantined

        """
        endpoint = '%s/%s' % (self._GetURL(), 'quarantine/continent')

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('QUARANTINECONTINENT GET Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.unauthorized:
            dto = model.QuarantineContinentResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            quarantine = response.json()['quarantined']
            dto = model.QuarantineContinentResponse(quarantine=quarantine)
            return dto

        return model.QuarantineContinentResponse(status_code=response.status_code, error=response.text)

    def GetQuarantineAS(self):
        """Get the list of Autonomous Systems quarantined

        """
        endpoint = '%s/%s' % (self._GetURL(), 'quarantine/as')

        response = requests.request("GET", endpoint, headers= {'X-Auth-Token': self._api_key, 'Accept': 'application/json'})

        _logger.debug('QUARANTINEAS GET Endpoint: %s. Response: %s:%s' % (endpoint, response.status_code, response.text))

        if response.status_code == requests.codes.unauthorized:
            dto = model.QuarantineASResponse(status_code=response.status_code, error='Bad Request.')
            return dto

        if response.status_code == requests.codes.ok:
            quarantine = response.json()['quarantined']
            dto = model.QuarantineASResponse(quarantine=quarantine)
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
            dto = model.Response(status_code=response.status_code, error='Bad Request.')
            return dto
        if response.status_code == requests.codes.ok:
            dto = model.Response(status_code=response.status_code, error='OK.')
            return dto
        return model.Response(status_code=response.status_code, error=response.text)

    def AddQuarantineIP(self, ip_address, ttl=3600):
        """Add an IP address to the list of quarantined IP addresses.

        """

        self._ValidateIP(ip_address)
        self._ValidateTTL(ttl)
        object_type = 'ip'

        return self._AddQuarantineObject(object_type, ip_address, ttl)

    def AddQuarantineCountry(self, country, ttl=3600):
        """Add a country to the list of quarantined countries' IP addresses.

        """

        self._ValidateCountry(country)
        self._ValidateTTL(ttl)
        object_type = 'country'

        return self._AddQuarantineObject(object_type, country, ttl)

    def AddQuarantineContinent(self, continent, ttl=3600):
        """Add a continent to the list of quarantined continents' IP addresses.

        """

        self._ValidateContinent(continent)
        self._ValidateTTL(ttl)
        object_type = 'continent'

        return self._AddQuarantineObject(object_type, continent, ttl)

    def AddQuarantineAS(self, asnum, ttl=3600):
        """Add a AS to the list of quarantined ASs' IP addresses.

        """

        self._ValidateASNum(asnum)
        self._ValidateTTL(ttl)
        object_type = 'asn'

        return self._AddQuarantineObject(object_type, asnum, ttl, object_uri_type='as')

    def _DeleteQuarantineObject(self, object_type, object_value):
        endpoint = '%s/%s/%s' % (self._GetURL(), 'quarantine/%s' % object_type, object_value)
        response = requests.request("DELETE", endpoint, headers={'X-Auth-Token': self._api_key})
        _logger.debug('QUARANTINE%s DELETE Endpoint: %s. Response: %s:%s' % (
        object_type.upper(), endpoint, response.status_code, response.text))
        if response.status_code == requests.codes.unauthorized:
            dto = model.Response(status_code=response.status_code, error='Bad Request.')
            return dto
        if response.status_code == requests.codes.ok:
            dto = model.Response(status_code=response.status_code, error='OK.')
            return dto
        return model.Response(status_code=response.status_code, error=response.text)

    def DeleteQuarantineIP(self, ip_address):
        """Delete an IP address of the list of quarantined IP addresses.

        """

        self._ValidateIP(ip_address)
        object_type = 'ip'

        return self._DeleteQuarantineObject(object_type, ip_address)

    def DeleteQuarantineCountry(self, country):
        """Delete a Country of the list of quarantined countries' IP addresses.

        """

        self._ValidateCountry(country)
        object_type = 'country'

        return self._DeleteQuarantineObject(object_type, country)

    def DeleteQuarantineContinent(self, continent):
        """Delete a Continent of the list of quarantined continents' IP addresses.

        """

        self._ValidateContinent(continent)
        object_type = 'continent'

        return self._DeleteQuarantineObject(object_type, continent)

    def DeleteQuarantineAS(self, asn):
        """Delete a AS of the list of quarantined ASs' IP addresses.

        """

        self._ValidateASNum(asn)
        object_type = 'as'

        return self._DeleteQuarantineObject(object_type, asn)
