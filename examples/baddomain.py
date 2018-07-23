import sys
import getopt
import os
import traceback

import apilityio
import apilityio.errors


def main(argv=None):
    if argv is None:
        argv = sys.argv
    try:
        try:
            api_key = None
            domain = None
            options, remainder = getopt.getopt(argv[1:], 'h:a:d', ['help', 'api_key=', 'domain='])
            for opt, arg in options:
                if opt in ('-a', '--api_key'):
                    api_key = arg
                if opt in ('-d', '--domain'):
                    try:
                        domain = unicode(arg, "utf-8")
                    except:
                        domain = arg
                elif opt in ('-h', '--help'):
                    print("python baddomain.py --api_key=<API_KEY> --domain=<DOMAIN>")
                    return 0
        except getopt.error as msg:
            raise Exception(msg)

        try:
            client = apilityio.Client(api_key=api_key)
            api_key, protocol, host = client.GetConnectionData()

            print('Host: %s' % host)
            print('Protocol: %s' % protocol)
            print('API Key: %s' % api_key)

            print('BadDomain FQDN: %s' % domain)

            response = client.CheckDomain(domain)

            if response.status_code != 200:
                print("The API call returned this error HTTP %s: %s" % (response.status_code, response.error))
                return 0

            dresponse = response.response
            print('+- Global score: %s' % dresponse.score)
            print('+--- Domain score: %s' % dresponse.domain.score)
            print('+--- Blacklist: %s' % dresponse.domain.blacklist)
            print('+--- Blacklist NS: %s' % dresponse.domain.blacklist_ns)
            print('+--- Blacklist MX: %s' % dresponse.domain.blacklist_mx)
            print('+--- NS: %s' % dresponse.domain.ns)
            print('+--- MX: %s' % dresponse.domain.mx)
            print('+')
            print('+--- IP score: %s' % dresponse.ip.score)
            print('+--- Blacklist: %s' % dresponse.ip.blacklist)
            print('+--- Quarantined? %s' % dresponse.ip.is_quarantined)
            print('+--- Address: %s' % dresponse.ip.address)
            print('+')
            print('+--- Source IP score: %s' % dresponse.source_ip.score)
            print('+--- Source Blacklist: %s' % dresponse.source_ip.blacklist)
            print('+--- Source Quarantined? %s' % dresponse.source_ip.is_quarantined)
            print('+--- Source Address: %s' % dresponse.source_ip.address)



        except apilityio.errors.ApilityioValueError as ae:
            traceback.print_exc()
            print("ERROR: ", ae)
            return 2

        return 0
    except Exception as e:
        traceback.print_exc()
        print("ERROR: ", e)
        print("For help, use --help")
        return 2


if __name__ == "__main__":
    sys.exit(main())



