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

import requests


class BaseDict(dict):
    """Create a Generic object from  dict.
    """

    def __getattr__(self, name):
        if name in self:
            return self[name]
        else:
            raise AttributeError("No such attribute: " + name)

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        if name in self:
            del self[name]
        else:
            raise AttributeError("No such attribute: " + name)


class Response(object):
    """Create a basic response object.

    Keyword Arguments:
      - ``status_code``: An integer with the HTTP response status code
      - ``error``: If status code is not 200 (OK), the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.

    Attributes:
      - ``status_code``: An integer with the HTTP response status code
      - ``error``: If status code is not 200 (OK), the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, json=None):
        self.status_code = status_code
        self.error = error
        self.json = json


class BadIPResponse(Response):
    """Response object with the result of a query to check if the IP address has been found in any blacklist.

    Keyword Arguments:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or 404 (NOT_FOUND), the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``blacklists``: List of strings with the name of the Blacklists of the IP.

    Attributes:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or 404 (NOT_FOUND), the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``blacklists``: List of strings with the name of the Blacklists of the IP.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, blacklists=[], json=None):
        super(BadIPResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        self.blacklists = blacklists


class IPBlacklist(object):
    """Object to pair IP adress and blacklists. This object contains an IP address and a list with the blacklists it was found.

        Keyword Arguments:
          - ``ip_address``: the ip address of the pair
          - ``blacklists``: the list of strings with the blacklists names of the IP address

        Attributes:
          - ``ip_address``: the ip address of the pair
          - ``blacklists``: the list of strings with the blacklists names of the IP address
        """

    def __init__(self, ip_address, blacklists):
        self.ip_address = ip_address
        self.blacklists = blacklists


class BadBatchIPResponse(Response):
    """Response object with the result of a query to check if a group of IP addresses have been found in any blacklist.

    Keyword Arguments:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK), the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``ipblacklists_set``: Set of :func:`~apilityio.model.IPBlacklist` objects that contains the result of the check performed on each IP address.

    Attributes:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK), the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``ipblacklists_set``: Set of :func:`~apilityio.model.IPBlacklist` objects that contains the result of the check performed on each IP address.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, ipblacklists_set=set(), json=None):
        super(BadBatchIPResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        self.ipblacklists_set = ipblacklists_set


class ContinentNames(dict):
    """Object to cointain all the translations of a continent.

    Keyword Arguments:
      - ``continent_names``: Dictionary containing all the names in different languages of a given continent.

    Attributes:
      - ``en``: English
      - ``pt-BR``: Portuguese
      - ``fr``: French
      - ``ja``: Japanes
      - ``de``: German
      - ``zh-CN``: Chinese
      - ``es``: Spanish
      - ``ru``: Russian
    """


class CountryNames(BaseDict):
    """Object to cointain all the translations of a country. It is only guaranteed to exists the english (en) attribute.

    Keyword Arguments:
      - ``country_names``: Dictionary containing all the names in different languages of a given country

    Attributes:
      - ``en``: English
      - ``pt-BR``: Portuguese
      - ``fr``: French
      - ``ja``: Japanes
      - ``de``: German
      - ``zh-CN``: Chinese
      - ``es``: Spanish
      - ``ru``: Russian
    """


class GeoIP(BaseDict):
    """Object to cointain all geolocation data of the IP address.

    Keyword Arguments:
      - ``geoip``: Dictionary containing all the geo location data as described in https://apility.io/apidocs/#geoip

    Attributes:
        - ``longitude``: Longitude where the IP has been found
        - ``latitude``: Latitude where the IP has been found
        - ``hostname``: Name of the host resolved from the IP
        - ``address``: IPv4 or IPv6 address of the request
        - ``continent``: 2 letter code of the continent.
        - ``country``: ISO 3166-1 Country code.
        - ``region``: Name of the region, by default the english translation in 'region_names'.
        - ``city``: Name of the city, by default the english translation in 'city_names'.
        - ``postal``: Postal code or Zip code
        - ``time_zone``: Time zone of the location
        - ``accuracy_radius``: The approximate radius in kilometers around the latitude and longitude for the geographical entity. -1 if unknown.
        - ``continent_geoname_id``: Id of the continent in the geonames.org database. -1 if the continent cannot be geolocated.
        - ``country_geoname_id``: Id of the country in the geonames.org database. -1 if the country cannot be geolocated.
        - ``region_geoname_id``: Id of the region in the geonames.org database. -1 if the region cannot be geolocated.
        - ``city_geoname_id``: Id of the city in the geonames.org database. -1 if the city cannot be geolocated.
        - ``continent_names``: Object containing the :func:`~apilityio.model.ContinentNames` data.
        - ``country_names``:  Object containing the :func:`~apilityio.model.CountryNames` data.
        - ``region_names``: JSON structure containing the different names of the region in different languages. Languages are in ISO 639-1. Empty if region cannot be geolocated.
        - ``city_names``: JSON structure containing the different names of the city in different languages. Languages are in ISO 639-1. Empty if city cannot be geolocated.
        - ``asystem``: Object containing the :func:`~apilityio.model.ASystem` data.
    """

    def __init__(self, geoip):
        super(GeoIP, self).__init__(geoip)
        self.country_names = CountryNames(geoip['country_names'])
        self.continent_names = ContinentNames(geoip['continent_names'])
        self.asystem = ASystem(geoip['as'])


class ASystem(BaseDict):
    """Object to cointain all the information of an Autonomous System.

    Keyword Arguments:
      - ``asystem``: Dictionary containing all the autonomous system information described in https://apility.io/apidocs/#as

    Attributes:
      - ``asn``: AS number
      - ``name``: name of the AS
      - ``country``: ISO 3166-1 Country code
      - ``networks``: List with the networks of the AS
    """


class GeoIPResponse(Response):
    """Response object with the result of a query to get the IP address geolocation data.

    Keyword Arguments:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``geoip``: Dictionary containing all the geo location data as described in https://apility.io/apidocs/#geoip

    Attributes:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``geoip``: Object :func:`~apilityio.model.GeoIP` containing all geolocation attributes.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, geoip=None, json=None):
        super(GeoIPResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        if geoip is not None and 'address' in geoip:
            self.geoip = GeoIP(geoip)
        else:
            self.geoip = None


class IPGeodata(object):
    """Object to pair IP adress and geodata information. This object contains an IP address and its geodata information.

        Keyword Arguments:
          - ``ip_address``: the ip address of the pair
          - ``geodata``: an Object :func:`~apilityio.model.GeoIP` object with the geodata information

        Attributes:
          - ``ip_address``: the ip address of the pair
          - ``geodata``: an Object :func:`~apilityio.model.GeoIP` object with the geodata information
        """

    def __init__(self, ip_address, geodata):
        self.ip_address = ip_address
        self.geoip = geodata


class GeoBatchIPResponse(Response):
    """Response object with the result of a query to get the geolocation data of multiple IP addresses.

        Keyword Arguments:
          - ``status_code``: An integer with the HTTP response status code
          - ``error``: If status code is not 200 (OK), the error returned by the server.
          - ``json``: JSON object returned by the REST API without modifications.
          - ``geolocated_ip_list``: List of :func:`~apilityio.model.IPGeodata` objects.

        Attributes:
          - ``status_code``: An integer with the HTTP response status code
          - ``error``: If status code is not 200 (OK), the error returned by the server.
          - ``json``: JSON object returned by the REST API without modifications.
          - ``geolocated_ip_list``: List of :func:`~apilityio.model.IPGeodata` objects.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, geolocated_ip_list=[], json=None):

        super(GeoBatchIPResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        self.geolocated_ip_list = geolocated_ip_list


class IP(BaseDict):
    """Object to cointain the information of the information of looking up the IP in the blacklists.

    Keyword Arguments:
      - ``ip_address``: Dictionary containing all the information of the IP in the blacklists as described in https://apility.io/apidocs/#ip-score

    Attributes:
      - ``score``: Number describing the result of the algorithm. Negative means 'suspicious' or 'bad' IP. Neutral or positive means it's a 'clean' IP.
      - ``blacklist``: List containing the blacklists where the IP was found.
      - ``is_quarantined``: If the IP has been added by the user to the quarantine lists.
      - ``address``: IPv4 or IPv6 resolved.
    """


class Domain(BaseDict):
    """Object to cointain the information of testing different subdomains of the main root domain: NS records, MX records and domain blacklists.

    Keyword Arguments:
      - ``domain``: Dictionary containing all the subdomains of the main root domain: NS records, MX records and domain as described in https://apility.io/apidocs/#domainname-score

    Attributes:
      - ``score``: Number describing the result of the algorithm. Negative means 'suspicious' or 'bad' domain. Neutral or positive means it's a 'clean' domain.
      - ``blacklist_ns``: List containing the blacklists where the NS domains were found.
      - ``blacklist_mx``: List containing the blacklists where the MX domains were found.
      - ``blacklist``: List containing the blacklists where the domain was found.
      - ``mx``: List with the hosts found in the MX records.
      - ``ns``: List with the hosts found in the NS records.
    """


class BadDomain(BaseDict):
    """Object to cointain all scoring and blacklist analysis for main Domain, MX and NS records and IP address.

    Keyword Arguments:
      - ``domain_data``: Dictionary containing all the domain analysis data as described in https://apility.io/apidocs/#domain

    Attributes:
      - ``score``: Number describing the result of the algorithm. Negative means 'suspicious' or 'bad' domain. Neutral or positivo means it's a 'clean' domain.
      - ``domain``: Object :func:`~apilityio.model.Domain` containing the 'domainname score' information as result of the analysis of the domains.
      - ``ip``: Object :func:`~apilityio.model.IP` containing the 'ip score' information as result of the analysis of the IP of the domain.
      - ``source_ip``: Object :func:`~apilityio.model.IP` containing the 'ip score' information as result of the analysis of the IP origin of the request.
    """

    def __init__(self, domain_data):
        super(BadDomain, self).__init__(domain_data)
        self.domain = Domain(domain_data['domain'])
        self.ip = IP(domain_data['ip'])
        self.source_ip = IP(domain_data['source_ip'])


class BadDomainResponse(Response):
    """Response object with the result of a query to check if the Domain and its MX and NS records have been found in any blacklist.

    Keyword Arguments:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or 404 (NOT_FOUND), the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``domain_data``: Dictionary containing all the domain analysis data as described in https://apility.io/apidocs/#domain

    Attributes:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or 404 (NOT_FOUND), the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``response``: Object :func:`~apilityio.model.BadDomain` containing all scoring and blacklists of the Domain.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, domain_data=None, json=None):
        super(BadDomainResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        if domain_data is not None:
            self.response = BadDomain(domain_data)
        else:
            self.response = None


class DomainScored(object):
    """Object to pair domain and the result of the scoring process

        Keyword Arguments:
          - ``domain``: the domain FQDN of the pair
          - ``scored_domain``: an Object :func:`~apilityio.model.BadDomain` with the scoring information

        Attributes:
          - ``domain``: the domain FQDN of the pair
          - ``scoring``: an Object :func:`~apilityio.model.BadDomain` with the scoring information
    """

    def __init__(self, domain, scored_domain):
        self.domain = domain
        self.scoring = scored_domain


class BadBatchDomainResponse(Response):
    """Response object with the result of a query to get the analysis data of multiple domains.

        Keyword Arguments:
          - ``status_code``: An integer with the HTTP response status code
          - ``error``: If status code is not 200 (OK), the error returned by the server.
          - ``json``: JSON object returned by the REST API without modifications.
          - ``domain_scoring_list``: List of :func:`~apilityio.model.DomainScored` objects.

        Attributes:
          - ``status_code``: An integer with the HTTP response status code
          - ``error``: If status code is not 200 (OK), the error returned by the server.
          - ``json``: JSON object returned by the REST API without modifications.
          - ``domain_scoring_list``: List of :func:`~apilityio.model.DomainScored` objects.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, domain_scoring_list=[], json=None):
        super(BadBatchDomainResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        self.domain_scoring_list = domain_scoring_list


class EmailAddress(BaseDict):
    """Object to cointain the information of the format of the Email address.

    Keyword Arguments:
      - ``address_score``: Dictionary containing all the address format details described in https://apility.io/apidocs/#address-score

    Attributes:
      - ``score``: Number describing the result of the algorithm. Negative means 'suspicious' or 'bad' IP. Neutral or positive means it's a 'clean' Email.
      - ``is_role``: True if the email has the format of a role-based-address. It's not common to allow registration with role-based-addresses.
      - ``is_well_formed``:	True if the email is compliant with the standard email formats.
    """


class SMTPInfo(BaseDict):
    """Object to cointain the information obtained after testing the remote inbox SMTP server where the email is hosted.

    Keyword Arguments:
      - ``smtp_score``: Dictionary containing all SMTP score test details in in https://apility.io/apidocs/#smtp-score

    Attributes:
      - ``score``: Number describing the result of the algorithm. Negative means 'suspicious' or 'bad' IP. Neutral or positive means it's a 'clean' Email.
      - ``exist_mx``: True if the SMTP service is reachable using the hosts in the MX records.
      - ``exist_address``: True if the SMTP service recognizes the email address.
      - ``exist_catchall``:	True if the SMTP service implements a catch-all email feature.
    """


class FreeEmail(BaseDict):
    """Object to cointain the information checking the domain against a list of Free domain servers.

    Keyword Arguments:
      - ``freemail_score``: Dictionary containing all Freemail score test details in in https://apility.io/apidocs/#freemail-score

    Attributes:
      - ``score``: Number describing the result of the algorithm. Negative means 'suspicious' or 'bad' IP. Neutral or positive means it's a 'clean' Email.
      - ``is_freemail``: True if the domain has been found in any Free Email Service Provider list.
    """


class EmailScore(BaseDict):
    """Object to cointain the information checking the email against a list of Email addresses of abusers.

    Keyword Arguments:
      - ``email_score``: Dictionary containing all Email of abusers score test details in in https://apility.io/apidocs/#email-score

    Attributes:
      - ``score``: Number describing the result of the algorithm. Negative means 'suspicious' or 'bad' IP. Neutral or positive means it's a 'clean' Email.
      - ``blacklist``: List containing the blacklists where the email was found.
    """


class DisposableEmail(BaseDict):
    """Object to cointain the information checking the domain against a list of Disposable Email Addresses.

    Keyword Arguments:
      - ``disposable_score``: Dictionary containing all Disposable score test details in in https://apility.io/apidocs/#disposable-score

    Attributes:
      - ``score``: Number describing the result of the algorithm. Negative means 'suspicious' or 'bad' IP. Neutral or positive means it's a 'clean' Email.
      - ``is_disposable``: True if The domain has been found in any Disposable Email Address Providers list.
    """


class BadEmail(BaseDict):
    """Object to cointain all scoring and blacklist analysis for Email about SMTP server, main Domain, MX and NS records and IP address.

    Keyword Arguments:
      - ``email_data``: Dictionary containing all the email analysis data as described in https://apility.io/apidocs/#email

    Attributes:
      - ``score``: Number describing the result of the algorithm. Negative means 'suspicious' or 'bad' domain. Neutral or positivo means it's a 'clean' email.
      - ``domain``: Object :func:`~apilityio.model.Domain` containing the 'domainname score' information as result of the analysis of the domains.
      - ``ip``: Object :func:`~apilityio.model.IP` containing the 'ip score' information as result of the analysis of the IP of the domain.
      - ``source_ip``: Object :func:`~apilityio.model.IP` containing the 'ip score' information as result of the analysis of the IP origin of the request.
      - ``address``: Object :func:`~apilityio.model.EmailAddress` containing the 'address score' object as result of the analysis of the email.
      - ``smtp``: Object :func:`~apilityio.model.SMTPInfo` containing the 'smtp score' object as result of the analysis of the email service.
      - ``freemail``: Object :func:`~apilityio.model.FreeEmail` containing the 'freemail score' object as result of the analysis of the email provider.
      - ``email``: Object :func:`~apilityio.model.EmailScore` containing the 'email-blacklist score' object as result of the look up in the email blacklists.
      - ``disposable``: Object :func:`~apilityio.model.DisposableEmail` containing the 'disposable score' object as result of the analysis of the email provider.
    """

    def __init__(self, email_data):
        super(BadEmail, self).__init__(email_data)
        self.domain = Domain(email_data['domain'])
        self.ip = IP(email_data['ip'])
        self.source_ip = IP(email_data['source_ip'])
        self.address = EmailAddress(email_data['address'])
        self.smtp = SMTPInfo(email_data['smtp'])
        self.freemail = FreeEmail(email_data['freemail'])
        self.email = EmailScore(email_data['email'])
        self.disposable = DisposableEmail(email_data['disposable'])


class BadEmailResponse(Response):
    """Response object with the result of a query to check if the Domain and its MX and NS records have been found in any blacklist.

    Keyword Arguments:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or 404 (NOT_FOUND), the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``email_data``: Dictionary containing all the email analysis data as described in https://apility.io/apidocs/#email

    Attributes:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or 404 (NOT_FOUND), the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``response``: Object :func:`~apilityio.model.BadEmail` containing all scoring and blacklists of the Email.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, email_data=None, json=None):
        super(BadEmailResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        if email_data is not None:
            self.response = BadEmail(email_data)
        else:
            self.response = None


class EmailScored(object):
    """Object to pair Email and the result of the scoring process

        Keyword Arguments:
          - ``email``: the email address of the pair
          - ``scored_email``: an Object :func:`~apilityio.model.BadEmail` with the scoring information

        Attributes:
          - ``email``: the email address of the pair
          - ``scoring``: an Object :func:`~apilityio.model.BadEmail` with the scoring information
    """

    def __init__(self, email, scored_email):
        self.email = email
        self.scoring = scored_email


class BadBatchEmailResponse(Response):
    """Response object with the result of a query to get the analysis data of multiple emails.

        Keyword Arguments:
          - ``status_code``: An integer with the HTTP response status code
          - ``error``: If status code is not 200 (OK), the error returned by the server.
          - ``json``: JSON object returned by the REST API without modifications.
          - ``email_scoring_list``: List of :func:`~apilityio.model.EmailScored` objects.

        Attributes:
          - ``status_code``: An integer with the HTTP response status code
          - ``error``: If status code is not 200 (OK), the error returned by the server.
          - ``json``: JSON object returned by the REST API without modifications.
          - ``email_scoring_list``: List of :func:`~apilityio.model.EmailScored` objects.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, email_scoring_list=[], json=None):
        super(BadBatchEmailResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        self.email_scoring_list = email_scoring_list


class ASResponse(Response):
    """Response object with the result of a query to get Autonomous System information.

    Keyword Arguments:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``asystem``: Dictionary containing all the autonomous system information described in https://apility.io/apidocs/#as

    Attributes:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``asystem``: Object :func:`~apilityio.model.ASystem` containing all autonomous system attributes.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, asystem=None, json=None):
        super(ASResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        if asystem is not None:
            self.asystem = ASystem(asystem)
        else:
            self.asystem = None


class ASBatchIPResponse(Response):
    """Response object with the result of a query to get the Autonomous System information of multiple IP addresses.

        Keyword Arguments:
          - ``status_code``: An integer with the HTTP response status code
          - ``error``: If status code is not 200 (OK), the error returned by the server.
          - ``json``: JSON object returned by the REST API without modifications.
          - ``asystem_ip_list``: List of :func:`~apilityio.model.IPASystem` objects.

        Attributes:
          - ``status_code``: An integer with the HTTP response status code
          - ``error``: If status code is not 200 (OK), the error returned by the server.
          - ``json``: JSON object returned by the REST API without modifications.
          - ``asystem_ip_list``: List of :func:`~apilityio.model.IPASystem` objects.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, asystem_ip_list=[], json=None):
        super(ASBatchIPResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        self.asystem_ip_list = asystem_ip_list


class IPASystem(object):
    """Object to pair IP adress and Autonomous System information. This object contains an IP address and its AS information.

        Keyword Arguments:
          - ``ip_address``: the ip address of the pair
          - ``as_data``: an Object :func:`~apilityio.model.ASystem` object with the autonomous system information

        Attributes:
          - ``ip_address``: the ip address of the pair
          - ``asystem``: an Object :func:`~apilityio.model.ASystem` object with the autonomous system  information
    """

    def __init__(self, ip_address, as_data):
        self.ip_address = ip_address
        self.asystem = as_data


class ASNASystem(object):
    """Object to pair AS numbers and Autonomous System information. This object contains an AS number and its AS information.

        Keyword Arguments:
          - ``as_number``: the AS number of the object.
          - ``as_data``: an Object :func:`~apilityio.model.ASystem` object with the autonomous system information

        Attributes:
          - ``asn``: the AS number of the object.
          - ``asystem``: an Object :func:`~apilityio.model.ASystem` object with the autonomous system  information
    """

    def __init__(self, as_number, as_data):
        self.asn = as_number
        self.asystem = as_data


class ASBatchNumResponse(Response):
    """Response object with the result of a query to get the Autonomous System information of multiple AS numbers.

        Keyword Arguments:
          - ``status_code``: An integer with the HTTP response status code
          - ``error``: If status code is not 200 (OK), the error returned by the server.
          - ``json``: JSON object returned by the REST API without modifications.
          - ``asystem_asn_list``: List of :func:`~apilityio.model.ASNASystem` objects.

        Attributes:
          - ``status_code``: An integer with the HTTP response status code
          - ``error``: If status code is not 200 (OK), the error returned by the server.
          - ``json``: JSON object returned by the REST API without modifications.
          - ``asystem_asn_list``: List of :func:`~apilityio.model.ASNASystem` objects.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, asystem_num_list=[], json=None):
        super(ASBatchNumResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        self.asystem_asn_list = asystem_num_list


class WhoisIPResponse(Response):
    """Response object with the result of a query to get WHOIS information of an IP address.

    Keyword Arguments:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``whois``: Dict structure with the WHOIS IP information described in https://apility.io/apidocs/#whois

    Attributes:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``whois``: Object :func:`~apilityio.model.WhoisIP` containing all WHOIS objects and attributes.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, whois=None, json=None):
        super(WhoisIPResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        if whois is not None:
            self.whois = WhoisIP(whois)
        else:
            self.whois = None


class WhoisIP(BaseDict):
    """Object to cointain all WHOIS data of the IP address.

    Keyword Arguments:
      - ``whois``: Dictionary containing all the WHOIS data as described in https://apility.io/apidocs/#whois

    Attributes:
        - ``query``: The IP address
        - ``asn``: Globally unique identifier used for routing information exchange with Autonomous Systems.
        - ``asn_cidr``: Network routing block assigned to an ASN.
        - ``asn_country_code``: ASN assigned country code in ISO 3166-1 format.
        - ``asn_date``: ASN allocation date in ISO 8601 format.
        - ``asn_registry``: ASN assigned regional internet registry.
        - ``asn_description``: The ASN description
        - ``network``: Object containing the :func:`~apilityio.model.WhoisNetwork` data.
        - ``entities``: list of object names referenced by an RIR network. Map these to the objects keys.
        - ``objects``: List of objects containing the :func:`~apilityio.model.WhoisObject` data.
    """

    def __init__(self, whois):
        super(WhoisIP, self).__init__(whois)
        self.network = WhoisNetwork(whois['network'])
        self.objects = [WhoisObject(value)
                        for key, value in whois['objects'].items()]


class WhoisObject(BaseDict):
    """Object to cointain all WHOIS data (entity) in the objects list within the WHOIS.

    Keyword Arguments:
      - ``whoisobject``: Dictionary containing all the WHOIS OBJECT data as described in https://apility.io/apidocs/#whois-object

    Attributes:
        - ``contact``: 	Object containing the :func:`~apilityio.model.WhoisObjectContact` data. Contact information registered with an RIR object.
        - ``entities``: List of object names referenced by an RIR object. Map these to other objects keys.
        - ``events``: List of objects containing the :func:`~apilityio.model.WhoisEvent` data. List of event dictionaries.
        - ``events_actor``: List of objects containing the :func:`~apilityio.model.WhoisEvent` as events (no actor).
        - ``handle``: Unique identifier for a registered object.
        - ``links``: List of HTTP/HTTPS links provided for an RIR object.
        - ``notices``: List of objects containing the :func:`~apilityio.model.WhoisNotice`. List of notice dictionaries.
        - ``remarks``:List of objects containing the :func:`~apilityio.model.WhoisNotice`.  List of remark (notice) dictionaries.
        - ``roles``: List of roles assigned to a registered object.
        - ``status``: List indicating the state of a registered object.
    """

    def __init__(self, whoisobject):
        super(WhoisObject, self).__init__(whoisobject)
        self.contact = WhoisObjectContact(whoisobject['contact'])
        events = whoisobject['events']
        if events:
            self.events = [WhoisEvent(event) for event in events]
        else:
            self.events = []
        notices = whoisobject['notices']
        if notices:
            self.notices = [WhoisNotice(notice) for notice in notices]
        else:
            self.notices = []
        remarks = whoisobject['remarks']
        if remarks:
            self.remarks = [WhoisRemark(remark) for remark in remarks]
        else:
            self.remarks = []


class WhoisNetwork(BaseDict):
    """Object to cointain all WHOIS data (entity) in the network within the WHOIS.

    Keyword Arguments:
      - ``whoisnetwork``: Dictionary containing all the WHOIS NETWORK data as described in https://apility.io/apidocs/#whois-network

    Attributes:
        - ``cidr``: Network routing block an IP address belongs to.
        - ``country``: Country code registered with the RIR in ISO 3166-1 format.
        - ``end_address``: The last IP address in a network block.
        - ``events``: List of objects containing the :func:`~apilityio.model.WhoisEvent` data. List of event dictionaries.
        - ``handle``: Unique identifier for a registered object.
        - ``ip_version``: IP protocol version (v4 or v6) of an IP address.
        - ``links``: HTTP/HTTPS links provided for an RIR object.
        - ``name``: The identifier assigned to the network registration for an IP address.
        - ``notices``: List of objects containing the :func:`~apilityio.model.WhoisNotice`. List of notice dictionaries.
        - ``parent_handle``: Unique identifier for the parent network of a registered network.
        - ``remarks``: List of objects containing the :func:`~apilityio.model.WhoisNotice`.  List of remark (notice) dictionaries.
        - ``start_address``: The first IP address in a network block.
        - ``status``: List indicating the state of a registered object.
        - ``type``: The RIR classification of a registered network.
    """

    def __init__(self, whoisnetwork):
        super(WhoisNetwork, self).__init__(whoisnetwork)
        events = whoisnetwork['events']
        if events:
            self.events = [WhoisEvent(event) for event in events]
        else:
            self.events = []
        notices = whoisnetwork['notices']
        if notices:
            self.notices = [WhoisNotice(notice) for notice in notices]
        else:
            self.notices = []
        remarks = whoisnetwork['remarks']
        if remarks:
            self.remarks = [WhoisRemark(remark) for remark in remarks]
        else:
            self.remarks = []


class WhoisEvent(BaseDict):
    """Object to cointain all WHOIS data (entity) in the events within the WHOIS.

    Keyword Arguments:
      - ``event``: Dictionary containing all the WHOIS EVENT data as described in https://apility.io/apidocs/#whois-event

    Attributes:
        - ``action``: The reason for an event.
        - ``timestamp``: The date an event occured in ISO 8601 format.
        - ``actor``: The identifier for an event initiator (if any).
    """


class WhoisNotice(BaseDict):
    """Object to cointain all WHOIS data (entity) in the notices within the WHOIS.

    Keyword Arguments:
      - ``notice``: Dictionary containing all the WHOIS NOTICE data as described in https://apility.io/apidocs/#whois-notice

    Attributes:
        - ``title``: The title/header for a notice.
        - ``description``: The description/body of a notice.
        - ``links``: list of HTTP/HTTPS links provided for a notice.
    """


class WhoisRemark(BaseDict):
    """Object to cointain all WHOIS data (entity) in the remarks within the WHOIS.

    Keyword Arguments:
      - ``remark``: Dictionary containing all the WHOIS REMARK data as described in https://apility.io/apidocs/#whois-notice

    Attributes:
        - ``title``: The title/header for a notice.
        - ``description``: The description/body of a notice.
        - ``links``: list of HTTP/HTTPS links provided for a notice.
    """


class WhoisObjectContact(BaseDict):
    """Object to cointain all WHOIS data (entity) in the object contact within the WHOIS.

    Keyword Arguments:
      - ``object_contact``: Dictionary containing all the WHOIS OBJECT CONTACT data as described in https://apility.io/apidocs/#whois-object-contact

    Attributes:
        - ``address``: List of contact postal address dictionaries. Contains key type and value.
        - ``email``: List of contact email address dictionaries. Contains key type and value.
        - ``kind``: The contact information kind (individual, group, org).
        - ``name``: The contact name.
        - ``phone``: List of contact phone number dictionaries. Contains key type and value.
        - ``role``: The contact's role.
        - ``title``: The contact's position or job title.
    """


class HistoryIPResponse(Response):
    """Response object with the result of a query to get the historical information of an IP address.

    Keyword Arguments:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``history``: Dict structure with the list of ip transactions described in https://apility.io/apidocs/#transaction-ip

    Attributes:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``history``: List of Objects :func:`~apilityio.model.HistoryIP` containing all transaction historical data.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, history=None, json=None):
        super(HistoryIPResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        self.history = []
        if history:
            for item in history:
                self.history.append(HistoryIP(item))


class HistoryIP(BaseDict):
    """Object to cointain the detals of a transaction of IP address in our database.

    Keyword Arguments:
      - ``transaction_ip``: Dictionary containing all the transaction IP address details as described in https://apility.io/apidocs/#transaction-ip

    Attributes:
        - ``timestamp``: The UNIX time in seconds when the transaction was performed.
        - ``command``: 'add' or 'rem'. Type of transaction in the database: ADD to the blacklist or REMove of the blacklist.
        - ``ip``: IP address of the transaction
        - ``blacklist_change``: Blackist added or removed thanks to the transaction.
        - ``blacklists``: List of blacklists after the execution of the command and the blacklist change.
    """


class HistoryDomainResponse(Response):
    """Response object with the result of a query to get the historical information of a domain.

    Keyword Arguments:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``history``: Dict structure with the list of domains transactions described in https://apility.io/apidocs/#transaction-domain

    Attributes:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``history``: List of Objects :func:`~apilityio.model.HistoryDomain` containing all transaction historical data.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, history=None, json=None):
        super(HistoryDomainResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        self.history = []
        if history:
            for item in history:
                self.history.append(HistoryDomain(item))


class HistoryDomain(BaseDict):
    """Object to cointain the detals of a transaction of domain in our database.

    Keyword Arguments:
      - ``transaction_domain``: Dictionary containing all the transaction domain details as described in https://apility.io/apidocs/#transaction-domain

    Attributes:
        - ``timestamp``: The UNIX time in seconds when the transaction was performed.
        - ``command``: 'add' or 'rem'. Type of transaction in the database: ADD to the blacklist or REMove of the blacklist.
        - ``domain``: Domain of the transaction
        - ``blacklist_change``: Blackist added or removed thanks to the transaction.
        - ``blacklists``: List of blacklists after the execution of the command and the blacklist change.
    """


class HistoryEmailResponse(Response):
    """Response object with the result of a query to get the historical information of an email.

    Keyword Arguments:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``history``: Dict structure with the list of email transactions described in https://apility.io/apidocs/#transaction-email

    Attributes:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``history``: List of Objects :func:`~apilityio.model.HistoryEmail` containing all transaction historical data.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, history=None, json=None):
        super(HistoryEmailResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        self.history = []
        if history:
            for item in history:
                self.history.append(HistoryEmail(item))


class HistoryEmail(BaseDict):
    """Object to cointain the detals of a transaction of email in our database.

    Keyword Arguments:
      - ``transaction_email``: Dictionary containing all the transaction email details as described in https://apility.io/apidocs/#transaction-email

    Attributes:
        - ``timestamp``: The UNIX time in seconds when the transaction was performed.
        - ``command``: 'add' or 'rem'. Type of transaction in the database: ADD to the blacklist or REMove of the blacklist.
        - ``email``: Email of the transaction
        - ``blacklist_change``: Blackist added or removed thanks to the transaction.
        - ``blacklists``: List of blacklists after the execution of the command and the blacklist change.
    """


class QuarantineIPResponse(Response):
    """Response object with the result of a query to get the IP addresses in the quarantine of the user.

    Keyword Arguments:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``quarantine``: Dict structure with the list of pairs of IP addresses and TTL to stay in the quarantine

    Attributes:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``quarantine``: List of Objects :func:`~apilityio.model.QuarantineIP` containing the pair IP address and TTL.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, quarantine=None, json=None):
        super(QuarantineIPResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        self.quarantine = []
        if quarantine:
            for item in quarantine:
                self.quarantine.append(QuarantineIP(item))


class QuarantineIP(BaseDict):
    """Object to cointain the IP address and the Time to Live of the IP address in the quarantine list.

    Keyword Arguments:
      - ``quarantine_ip``: Dictionary containing the IP address and the TTL.

    Attributes:
        - ``ip``: IP address to add to QUARANTINE-IP blacklist.
        - ``ttl``: Time to Live in seconds of the IP in the blacklist.
    """


class QuarantineCountryResponse(Response):
    """Response object with the result of a query to get the countries in the quarantine of the user.

    Keyword Arguments:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``quarantine``: Dict structure with the list of pairs of countries and TTL to stay in the quarantine

    Attributes:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``quarantine``: List of Objects :func:`~apilityio.model.QuarantineCountry` containing the pair Country and TTL.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, quarantine=None, json=None):
        super(QuarantineCountryResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        self.quarantine = []
        if quarantine:
            for item in quarantine:
                self.quarantine.append(QuarantineCountry(item))


class QuarantineCountry(BaseDict):
    """Object to cointain the Country and the Time to Live of the country in the quarantine list.

    Keyword Arguments:
      - ``quarantine_country``: Dictionary containing the Country and the TTL.

    Attributes:
        - ``country``: Country to add to QUARANTINE-COUNTRY blacklist.
        - ``ttl``: Time to Live in seconds of the country in the blacklist.
    """


class QuarantineContinentResponse(Response):
    """Response object with the result of a query to get the continents in the quarantine of the user.

    Keyword Arguments:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``quarantine``: Dict structure with the list of pairs of continents and TTL to stay in the quarantine

    Attributes:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``quarantine``: List of Objects :func:`~apilityio.model.QuarantineContinent` containing the pair Continent and TTL.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, quarantine=None, json=None):
        super(QuarantineContinentResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        self.quarantine = []
        if quarantine:
            for item in quarantine:
                self.quarantine.append(QuarantineContinent(item))


class QuarantineContinent(BaseDict):
    """Object to cointain the Continent and the Time to Live of the continent in the quarantine list.

    Keyword Arguments:
      - ``quarantine_continent``: Dictionary containing the Continent and the TTL.

    Attributes:
        - ``continent``: Country to add to QUARANTINE-CONTINENT blacklist.
        - ``ttl``: Time to Live in seconds of the continent in the blacklist.
    """


class QuarantineASResponse(Response):
    """Response object with the result of a query to get the Autonomous System in the quarantine of the user.

    Keyword Arguments:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``quarantine``: Dict structure with the list of pairs of AS and TTL to stay in the quarantine

    Attributes:
      - ``status_code``: An integer with the HTTP response status code. See https://apility.io/apidocs/#errors
      - ``error``: If status code is not 200 (OK) or the error returned by the server.
      - ``json``: JSON object returned by the REST API without modifications.
      - ``quarantine``: List of Objects :func:`~apilityio.model.QuarantineAS` containing the pair AS and TTL.
    """

    def __init__(self, status_code=requests.codes.ok, error=None, quarantine=None, json=None):
        super(QuarantineASResponse, self).__init__(
            status_code=status_code, error=error, json=json)
        self.quarantine = []
        if quarantine:
            for item in quarantine:
                self.quarantine.append(QuarantineAS(item))


class QuarantineAS(BaseDict):
    """Object to cointain the AS and the Time to Live of the continent in the quarantine list.

    Keyword Arguments:
      - ``quarantine_as``: Dictionary containing the AS and the TTL.

    Attributes:
        - ``asn``: Country to add to QUARANTINE-AS blacklist.
        - ``ttl``: Time to Live in seconds of the continent in the blacklist.
    """
