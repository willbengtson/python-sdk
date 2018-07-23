.. _quickstart:

Quickstart
==========

API Documentation
-----------------
You can read the Python documentation in :ref:`apireference`.


Full Examples
-------------
If you would like to obtain example code for any of the included client libraries, you can find it on our **examples** folder in our Github pages.


Import the library
------------------
The developer has to import the library **apilityio**

.. code-block:: python

   import apilityio


Import external libraries
-------------------------
If the developer has already installed the library with **pip** he/she should not care about the dependencies, but the libraries needed are:

- requests>=2.0.0,<3.0.0
- validators>=0.12.2,<1.0.0

If you are running Python 2.7.x, then you also need these libraries:

- py2-ipaddress<=3.4.1;python_version<"3.4


Create the client object
------------------------
The developer has to instance an object first passing as argument the API_KEY obtained after registering in https://apility.io.

It's possible to use the API without an API key, but it will be restricted to only 100 hits per day. Trial plan offers 1000 hits per day for 30 days and Free plan has 250 hits per day forever. Please read our pricing plans at https://apility.io/pricing.

To instantiate the client class with an API key:

.. code-block:: python

    client = apilityio.Client(api_key=api_key)


To instantiate the client class without an API key:

.. code-block:: python

    client = apilityio.Client()


Execute API calls
-----------------

Now it's time to perform the API calls. For example to look up an IP address in Apility.io databases of blacklists:

.. code-block:: python

    response = client.CheckIP(ip)


If the IP address has been not found in any blacklist, it will return a 404 code in the `status_code` attribute of the `Response` object:

.. code-block:: python

    if response.status_code == 404:
        print("Congratulations! The IP address has not been found in any blacklist.")

If the IP address has been not in any blacklist, it will return a 200 code in the `status_code` attribute of the `Response` object, and the lists of blacklists in the `blacklists` attribute:

.. code-block:: python

    if response.status_code == 200:
        print("Ooops! The IP address has been found in one or more blacklist")
        blacklists = response.blacklists
        print('+- Blacklists: %s' % blacklists)

Now the developer can perform as many requests as needed with this client object. And he/she doesn't need to close the connection because it is stateless.

What's next
-----------
The developer can start using the API right away, even without registering in the service! If you have any question you can visit the website at https://apility.io, review the REST API specification at https://apility.io/apidocs and also read the User Guide at https://apility.io/docs.

