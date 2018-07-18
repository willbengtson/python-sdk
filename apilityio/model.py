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
    """

    def __init__(self, status_code = requests.codes.ok, error = None):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.

        """
        self.status_code = status_code
        self.error = error

class BadIPResponse(Response):
    """Create a basic response object.
    """

    def __init__(self, status_code = requests.codes.ok, error = None, blacklists = []):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          blacklists: Array list of strings with the name of the Blacklists of the IP
        """
        super(BadIPResponse, self).__init__(status_code = status_code, error = error)
        self.blacklists = blacklists

class IPBlacklist(object):
    """Create an object to pair IP with blacklists
    """

    def __init__(self, ip_address, blacklists):
        """Initializes the pair object

        Keyword Arguments:
          ip_address: the ip address of the pair
          blacklists: the array of strings with the blacklists names of the IP address
        """
        self.ip_address = ip_address
        self.blacklists = blacklists


class BadBatchIPResponse(Response):
    """Create a response object for the Batch Bad IP request
    """

    def __init__(self, status_code = requests.codes.ok, error = None, ipblacklists_set = set()):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          ipblacklists_set: Set of IPBlacklist objects
        """
        super(BadBatchIPResponse, self).__init__(status_code = status_code, error = error)
        self.ipblacklists_set = ipblacklists_set


class ContinentNames(dict):
    """Create a CountryNames object from response dict.
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

class CountryNames(dict):
    """Create a CountryNames object from response dict.
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

class GeoIP(dict):
    """Create a Geo IP object from response dict.
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

    def __init__(self, geoip):
        super(GeoIP, self).__init__(geoip)
        self.country_names = CountryNames(geoip['country_names'])
        self.continent_names = ContinentNames(geoip['continent_names'])
        self.asystem = ASystem(geoip['as'])

class ASystem(dict):
    """Create a AS object from response dict.
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

class GeoIPResponse(Response):
    """Create a Geo IP response object.
    """
    def __init__(self, status_code = requests.codes.ok, error = None, geoip = None):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          geoip: Dict structure with the geoip information
        """
        super(GeoIPResponse, self).__init__(status_code = status_code, error = error)
        if geoip is not None and 'address' in geoip:
            self.geoip = GeoIP(geoip)
        else:
            self.geoip = None

class IPGeodata(object):
    """Create an object to pair IP with its geodata
    """

    def __init__(self, ip_address, geodata):
        """Initializes the pair object

        Keyword Arguments:
          ip_address: the ip address of the pair
          geodata: a GeoIP object with the geodata information
        """
        self.ip_address = ip_address
        self.geoip = geodata

class GeoBatchIPResponse(Response):
    """Create a response object for the Batch Geo IP request
    """

    def __init__(self, status_code = requests.codes.ok, error = None, geolocated_ip_list = []):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          geolocated_ip_list: List of IPGeodata objects
        """
        super(GeoBatchIPResponse, self).__init__(status_code = status_code, error = error)
        self.geolocated_ip_list = geolocated_ip_list

class IP(dict):
    """Create a IP address object from response dict.
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

class Domain(dict):
    """Create a Domain object from response dict.
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

class BadDomain(dict):
    """Create a Bad Domain object from response dict.
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

    def __init__(self, domain_data):
        super(BadDomain, self).__init__(domain_data)
        self.domain = Domain(domain_data['domain'])
        self.ip = IP(domain_data['ip'])
        self.source_ip = IP(domain_data['source_ip'])

class BadDomainResponse(Response):
    """Create a Bad Domain response object.
    """
    def __init__(self, status_code = requests.codes.ok, error = None, domain_data = None):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          domain_data: Dict structure with the bad domain information
        """
        super(BadDomainResponse, self).__init__(status_code = status_code, error = error)
        if domain_data is not None:
            self.response = BadDomain(domain_data)
        else:
            self.response = None

class DomainScored(object):
    """Create an object to pair domain and the result of the scoring process
    """

    def __init__(self, domain, scored_domain):
        """Initializes the pair object

        Keyword Arguments:
          domain: the domain of the pair
          scored_domain: a Domain object with the scoring information
        """
        self.domain = domain
        self.scoring = scored_domain

class BadBatchDomainResponse(Response):
    """Create a response object for the Batch Bad Domain request
    """

    def __init__(self, status_code = requests.codes.ok, error = None, domain_scoring_list = []):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          domain_list: List of domain and scoring objects
        """
        super(BadBatchDomainResponse, self).__init__(status_code = status_code, error = error)
        self.domain_scoring_list = domain_scoring_list

class EmailAddress(BaseDict):
    """Create an EmailAddress object from a dict.
    """

class SMTPInfo(BaseDict):
    """Create an SMTPInfo object from a dict.
    """

class FreeEmail(BaseDict):
    """Create an FreeEmail object from a dict.
    """

class EmailScore(BaseDict):
    """Create an Email Score object from a dict.
    """

class DisposableEmail(BaseDict):
    """Create an Disposable Email object from a dict.
    """

class BadEmail(BaseDict):
    """Create a Bad Email object from response dict.
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
    """Create a Bad Email response object.
    """
    def __init__(self, status_code = requests.codes.ok, error = None, email_data = None):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          email_data: Dict structure with the bad email information
        """
        super(BadEmailResponse, self).__init__(status_code = status_code, error = error)
        if email_data is not None:
            self.response = BadEmail(email_data)
        else:
            self.response = None

class EmailScored(object):
    """Create an object to pair email and the result of the scoring process
    """

    def __init__(self, email, scored_email):
        """Initializes the pair object

        Keyword Arguments:
          domain: the domain of the pair
          scored_email: an Email object with the scoring information
        """
        self.email = email
        self.scoring = scored_email

class BadBatchEmailResponse(Response):
    """Create a response object for the Batch Bad Email request
    """

    def __init__(self, status_code = requests.codes.ok, error = None, email_scoring_list = []):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          email_scoring_list: List of email and scoring objects
        """
        super(BadBatchEmailResponse, self).__init__(status_code = status_code, error = error)
        self.email_scoring_list = email_scoring_list

class ASResponse(Response):
    """Create a Autonmous System (AS) response object.
    """
    def __init__(self, status_code = requests.codes.ok, error = None, asystem = None):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          asystem: Dict structure with the AS information
        """
        super(ASResponse, self).__init__(status_code = status_code, error = error)
        if asystem is not None:
            self.asystem = ASystem(asystem)
        else:
            self.asystem = None

class ASBatchIPResponse(Response):
    """Create a response object for the Batch AS IP request
    """

    def __init__(self, status_code = requests.codes.ok, error = None, asystem_ip_list = []):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          asystem_ip_list: List of IPASystem objects
        """
        super(ASBatchIPResponse, self).__init__(status_code = status_code, error = error)
        self.asystem_ip_list = asystem_ip_list

class IPASystem(object):
    """Create an object to pair IP with its AS data
    """

    def __init__(self, ip_address, as_data):
        """Initializes the pair object

        Keyword Arguments:
          ip_address: the ip address of the pair
          as_data: a ASystem object with the AS information
        """
        self.ip_address = ip_address
        self.asystem = as_data

class ASNASystem(object):
    """Create an object to pair ASN with its AS data
    """

    def __init__(self, as_number, as_data):
        """Initializes the pair object

        Keyword Arguments:
          ip_address: the ip address of the pair
          as_data: a ASystem object with the AS information
        """
        self.asn = as_number
        self.asystem = as_data

class ASBatchNumResponse(Response):
    """Create a response object for the Batch AS ASN request
    """

    def __init__(self, status_code = requests.codes.ok, error = None, asystem_num_list = []):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          asystem_asn_list: List of ASNASystem objects
        """
        super(ASBatchNumResponse, self).__init__(status_code = status_code, error = error)
        self.asystem_asn_list = asystem_num_list

class WhoisIPResponse(Response):
    """Create a WHOIS IP response object.
    """
    def __init__(self, status_code = requests.codes.ok, error = None, whois = None):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          whois: Dict structure with the WHOIS IP information
        """
        super(WhoisIPResponse, self).__init__(status_code = status_code, error = error)
        if whois is not None:
            self.whois = WhoisIP(whois)
        else:
            self.whois = None

class WhoisIP(BaseDict):
    """Create a WhoisIP object from response dict.
    """
    def __init__(self, whois):
        super(WhoisIP, self).__init__(whois)
        self.network = WhoisNetwork(whois['network'])
        self.objects = [WhoisObject(value) for key, value in whois['objects'].items()]

class WhoisObject(BaseDict):
    """Create a WhoisIP Object object from response dict.
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
        remarks =  whoisobject['remarks']
        if remarks:
            self.remarks = [WhoisRemark(remark) for remark in remarks]
        else:
            self.remarks = []

class WhoisNetwork(BaseDict):
    """Create a WhoisIP Network object from response dict.
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
        remarks =  whoisnetwork['remarks']
        if remarks:
            self.remarks = [WhoisRemark(remark) for remark in remarks]
        else:
            self.remarks = []
class WhoisEvent(BaseDict):
    """Create a WhoisIP Event object from response dict.
    """

class WhoisNotice(BaseDict):
    """Create a WhoisIP Notice object from response dict.
    """

class WhoisRemark(BaseDict):
    """Create a WhoisIP Remark object from response dict.
    """

class WhoisObjectContact(BaseDict):
    """Create a WhoisIP Object contact object from response dict.
    """

class HistoryIPResponse(Response):
    """Create a History IP changes response object.
    """
    def __init__(self, status_code = requests.codes.ok, error = None, history = None):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          history: Dict structure with the History IP changes information
        """
        super(HistoryIPResponse, self).__init__(status_code = status_code, error = error)
        self.history = []
        if history:
            for item in history:
                self.history.append(HistoryIP(item))

class HistoryIP(BaseDict):
    """Create a History IP  object from response dict.
    """

class HistoryDomainResponse(Response):
    """Create a History Domain changes response object.
    """
    def __init__(self, status_code = requests.codes.ok, error = None, history = None):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          history: Dict structure with the History Domain changes information
        """
        super(HistoryDomainResponse, self).__init__(status_code = status_code, error = error)
        self.history = []
        if history:
            for item in history:
                self.history.append(HistoryDomain(item))

class HistoryDomain(BaseDict):
    """Create a History Domain  object from response dict.
    """

class HistoryEmailResponse(Response):
    """Create a History Email changes response object.
    """
    def __init__(self, status_code = requests.codes.ok, error = None, history = None):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          history: Dict structure with the History Email changes information
        """
        super(HistoryEmailResponse, self).__init__(status_code = status_code, error = error)
        self.history = []
        if history:
            for item in history:
                self.history.append(HistoryEmail(item))

class HistoryEmail(BaseDict):
    """Create a History Email object from response dict.
    """

class QuarantineIPResponse(Response):
    """Create a object with the list of Quarantined IP  response object.
    """
    def __init__(self, status_code = requests.codes.ok, error = None, quarantine = None):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          quarantine: Dict structure with the list of Quarantined IP information
        """
        super(QuarantineIPResponse, self).__init__(status_code = status_code, error = error)
        self.quarantine = []
        if quarantine:
            for item in quarantine:
                self.quarantine.append(QuarantineIP(item))

class QuarantineIP(BaseDict):
    """Create a Quarantine per IP object from response dict.
    """

class QuarantineCountryResponse(Response):
    """Create a object with the list of Quarantined Country  response object.
    """
    def __init__(self, status_code = requests.codes.ok, error = None, quarantine = None):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          quarantine: Dict structure with the list of Quarantined Countries information
        """
        super(QuarantineCountryResponse, self).__init__(status_code = status_code, error = error)
        self.quarantine = []
        if quarantine:
            for item in quarantine:
                self.quarantine.append(QuarantineCountry(item))

class QuarantineCountry(BaseDict):
    """Create a Quarantine per Country object from response dict.
    """

class QuarantineContinentResponse(Response):
    """Create a object with the list of Quarantined Continent  response object.
    """
    def __init__(self, status_code = requests.codes.ok, error = None, quarantine = None):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          quarantine: Dict structure with the list of Quarantined Continent information
        """
        super(QuarantineContinentResponse, self).__init__(status_code = status_code, error = error)
        self.quarantine = []
        if quarantine:
            for item in quarantine:
                self.quarantine.append(QuarantineContinent(item))

class QuarantineContinent(BaseDict):
    """Create a Quarantine per Continent object from response dict.
    """

class QuarantineASResponse(Response):
    """Create a object with the list of Quarantined AS  response object.
    """
    def __init__(self, status_code = requests.codes.ok, error = None, quarantine = None):
        """Initializes an ApilityioClient.

        Keyword Arguments:
          status_code: An integer with the HTTP response status code
          error: If status code is not 200 (OK), the error returned by the server.
          quarantine: Dict structure with the list of Quarantined AS information
        """
        super(QuarantineASResponse, self).__init__(status_code = status_code, error = error)
        self.quarantine = []
        if quarantine:
            for item in quarantine:
                self.quarantine.append(QuarantineAS(item))

class QuarantineAS(BaseDict):
    """Create a Quarantine per AS object from response dict.
    """

