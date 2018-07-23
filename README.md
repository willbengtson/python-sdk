Apility.io Python Client Library
================================

[![Documentation Status](https://readthedocs.org/projects/apilityio-python-lib/badge/?version=latest)](https://apilityio-python-lib.readthedocs.io/en/latest/?badge=latest)
[![Build Status](https://travis-ci.org/Apilityio/python-lib.svg?branch=dev)](https://travis-ci.org/Apilityio/python-lib)


Introduction
------------

Apility.io can be defined as Threat Intelligence SaaS for developers and product companies that want to know in realtime if their existing or potential users have been classified as 'abusers' by one or more of these lists.

Automatic extraction processes extracts all the information in realtime, keeping the most up to date data available, saving yourself the hassle of extract and update regularly all these lists and the data.


What does Apility.io offer?
---------------------------

Apility.io offers an extremely simple and minimalistic API to access in realtime to these lists and do the following simple question about the resource?

Is this IP, domain or email stored in any blacklist?

The answers to this question can be:

* YES: The resource can be found in an abusers' list. This is a bad resource.
* NO: The resource cannot be found in any abusers' list. This is a clean resource.

A bad resource implies some kind of action from developers' side. A clean resource does not need any action from their side.


Supported Python Versions
-------------------------

This library is supported for Python 2 and 3, for versions 2.7+ and 3.4+ respectively. It is recommended that Python 2 users use python 2.7.9+ to take advantage of the SSL Certificate Validation feature that is not included in earlier versions.

Installation
------------

You can install the Apility.io Python Client Library with _pip_:

```

   $ sudo pip install apilityio-lib

```

API Documentation
-----------------
You can read the Python documentation here: http://apilityio-python-lib.readthedocs.io/en/latest/

You can also read the original REST API specification here: https://apility.io/apidocs

Examples
--------
If you would like to obtain example code for any of the included client libraries, you can find it on our **examples** folder.

Contact Us
----------
Do you have an issue using the Apilityio Client Libraries? Or perhaps some feedback for how we can improve them? Feel free to let us know on our _`issue tracker <https://github.com/Apilityio/python-lib/issues>`_.
