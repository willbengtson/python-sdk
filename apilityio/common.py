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

import logging
import logging.config
import os
import ssl
import sys

try:
    import urllib2.HTTPSHandler
except ImportError:
    # Python versions below 2.7.9 / 3.4 won't have this. In order to offer legacy
    # support (for now) we will work around this gracefully, but users will
    # not have certificate validation performed until they update.
    pass

DEFAULT_LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'default': {
            'level': 'INFO',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        '': {
            'handlers': ['default'],
            'level': 'DEBUG',
            'propagate': True
        },
        'requests': {
            'handlers': ['default'],
            'level': 'WARN',
            'propagate': False
        },
    }
}

logging.config.dictConfig(DEFAULT_LOGGING)
_logger = logging.getLogger(__name__)

_PY_VERSION_MAJOR = sys.version_info.major
_PY_VERSION_MINOR = sys.version_info.minor
_PY_VERSION_MICRO = sys.version_info.micro
_DEPRECATED_VERSION_TEMPLATE = (
    'This library is being run by an unsupported Python version (%s.%s.%s). In '
    'order to benefit from important security improvements and ensure '
    'compatibility with this library, upgrade to Python 2.7.9 or higher.')

VERSION = '0.0.1'
_COMMON_LIB_SIG = 'apilityio/%s' % VERSION
_LOGGING_KEY = 'logging'
_PYTHON_VERSION = 'Python/%d.%d.%d' % (_PY_VERSION_MAJOR, _PY_VERSION_MINOR, _PY_VERSION_MICRO)

DEFAULT_HOST = 'api.apility.net'
HTTPS_PROTOCOL = 'https'
HTTP_PROTOCOL = 'http'

COUNTRIES = {"AF": "Afghanistan", "AX": "\u00c5land Islands", "AL": "Albania", "DZ": "Algeria", "AS": "American Samoa",
             "AD": "Andorra", "AO": "Angola", "AI": "Anguilla", "AQ": "Antarctica", "AG": "Antigua & Barbuda",
             "AR": "Argentina", "AM": "Armenia", "AW": "Aruba", "AC": "Ascension Island", "AU": "Australia",
             "AT": "Austria", "AZ": "Azerbaijan", "BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh",
             "BB": "Barbados", "BY": "Belarus", "BE": "Belgium", "BZ": "Belize", "BJ": "Benin", "BM": "Bermuda",
             "BT": "Bhutan", "BO": "Bolivia", "BA": "Bosnia & Herzegovina", "BW": "Botswana", "BR": "Brazil",
             "IO": "British Indian Ocean Territory", "VG": "British Virgin Islands", "BN": "Brunei", "BG": "Bulgaria",
             "BF": "Burkina Faso", "BI": "Burundi", "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada",
             "IC": "Canary Islands", "CV": "Cape Verde", "BQ": "Caribbean Netherlands", "KY": "Cayman Islands",
             "CF": "Central African Republic", "EA": "Ceuta & Melilla", "TD": "Chad", "CL": "Chile", "CN": "China",
             "CX": "Christmas Island", "CC": "Cocos (Keeling) Islands", "CO": "Colombia", "KM": "Comoros",
             "CG": "Congo - Brazzaville", "CD": "Congo - Kinshasa", "CK": "Cook Islands", "CR": "Costa Rica",
             "CI": "C\u00f4te d\u2019Ivoire", "HR": "Croatia", "CU": "Cuba", "CW": "Cura\u00e7ao", "CY": "Cyprus",
             "CZ": "Czechia", "DK": "Denmark", "DG": "Diego Garcia", "DJ": "Djibouti", "DM": "Dominica",
             "DO": "Dominican Republic", "EC": "Ecuador", "EG": "Egypt", "SV": "El Salvador", "GQ": "Equatorial Guinea",
             "ER": "Eritrea", "EE": "Estonia", "ET": "Ethiopia", "EZ": "Eurozone", "FK": "Falkland Islands",
             "FO": "Faroe Islands", "FJ": "Fiji", "FI": "Finland", "FR": "France", "GF": "French Guiana",
             "PF": "French Polynesia", "TF": "French Southern Territories", "GA": "Gabon", "GM": "Gambia",
             "GE": "Georgia", "DE": "Germany", "GH": "Ghana", "GI": "Gibraltar", "GR": "Greece", "GL": "Greenland",
             "GD": "Grenada", "GP": "Guadeloupe", "GU": "Guam", "GT": "Guatemala", "GG": "Guernsey", "GN": "Guinea",
             "GW": "Guinea-Bissau", "GY": "Guyana", "HT": "Haiti", "HN": "Honduras", "HK": "Hong Kong SAR China",
             "HU": "Hungary", "IS": "Iceland", "IN": "India", "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq",
             "IE": "Ireland", "IM": "Isle of Man", "IL": "Israel", "IT": "Italy", "JM": "Jamaica", "JP": "Japan",
             "JE": "Jersey", "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya", "KI": "Kiribati", "XK": "Kosovo",
             "KW": "Kuwait", "KG": "Kyrgyzstan", "LA": "Laos", "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho",
             "LR": "Liberia", "LY": "Libya", "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg",
             "MO": "Macau SAR China", "MK": "Macedonia", "MG": "Madagascar", "MW": "Malawi", "MY": "Malaysia",
             "MV": "Maldives", "ML": "Mali", "MT": "Malta", "MH": "Marshall Islands", "MQ": "Martinique",
             "MR": "Mauritania", "MU": "Mauritius", "YT": "Mayotte", "MX": "Mexico", "FM": "Micronesia",
             "MD": "Moldova", "MC": "Monaco", "MN": "Mongolia", "ME": "Montenegro", "MS": "Montserrat", "MA": "Morocco",
             "MZ": "Mozambique", "MM": "Myanmar (Burma)", "NA": "Namibia", "NR": "Nauru", "NP": "Nepal",
             "NL": "Netherlands", "NC": "New Caledonia", "NZ": "New Zealand", "NI": "Nicaragua", "NE": "Niger",
             "NG": "Nigeria", "NU": "Niue", "NF": "Norfolk Island", "KP": "North Korea",
             "MP": "Northern Mariana Islands", "NO": "Norway", "OM": "Oman", "PK": "Pakistan", "PW": "Palau",
             "PS": "Palestinian Territories", "PA": "Panama", "PG": "Papua New Guinea", "PY": "Paraguay", "PE": "Peru",
             "PH": "Philippines", "PN": "Pitcairn Islands", "PL": "Poland", "PT": "Portugal", "PR": "Puerto Rico",
             "QA": "Qatar", "RE": "R\u00e9union", "RO": "Romania", "RU": "Russia", "RW": "Rwanda", "WS": "Samoa",
             "SM": "San Marino", "ST": "S\u00e3o Tom\u00e9 & Pr\u00edncipe", "SA": "Saudi Arabia", "SN": "Senegal",
             "RS": "Serbia", "SC": "Seychelles", "SL": "Sierra Leone", "SG": "Singapore", "SX": "Sint Maarten",
             "SK": "Slovakia", "SI": "Slovenia", "SB": "Solomon Islands", "SO": "Somalia", "ZA": "South Africa",
             "GS": "South Georgia & South Sandwich Islands", "KR": "South Korea", "SS": "South Sudan", "ES": "Spain",
             "LK": "Sri Lanka", "BL": "St. Barth\u00e9lemy", "SH": "St. Helena", "KN": "St. Kitts & Nevis",
             "LC": "St. Lucia", "MF": "St. Martin", "PM": "St. Pierre & Miquelon", "VC": "St. Vincent & Grenadines",
             "SD": "Sudan", "SR": "Suriname", "SJ": "Svalbard & Jan Mayen", "SZ": "Swaziland", "SE": "Sweden",
             "CH": "Switzerland", "SY": "Syria", "TW": "Taiwan", "TJ": "Tajikistan", "TZ": "Tanzania", "TH": "Thailand",
             "TL": "Timor-Leste", "TG": "Togo", "TK": "Tokelau", "TO": "Tonga", "TT": "Trinidad & Tobago",
             "TA": "Tristan da Cunha", "TN": "Tunisia", "TR": "Turkey", "TM": "Turkmenistan",
             "TC": "Turks & Caicos Islands", "TV": "Tuvalu", "UM": "U.S. Outlying Islands", "VI": "U.S. Virgin Islands",
             "UG": "Uganda", "UA": "Ukraine", "AE": "United Arab Emirates", "GB": "United Kingdom",
             "UN": "United Nations", "US": "United States", "UY": "Uruguay", "UZ": "Uzbekistan", "VU": "Vanuatu",
             "VA": "Vatican City", "VE": "Venezuela", "VN": "Vietnam", "WF": "Wallis & Futuna", "EH": "Western Sahara",
             "YE": "Yemen", "ZM": "Zambia", "ZW": "Zimbabwe"}

COUNTRY_LIST = [*COUNTRIES]
CONTINENT_LIST = ["EU", "AS", "NA", "AF", "AN", "SA", "OC"]