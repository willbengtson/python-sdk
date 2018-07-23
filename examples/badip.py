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
            ip = None
            options, remainder = getopt.getopt(argv[1:], 'h:a:i', ['help', 'api_key=', 'ip='])
            for opt, arg in options:
                if opt in ('-a', '--api_key'):
                    api_key = arg
                if opt in ('-i', '--ip'):
                    try:
                        ip = unicode(arg, "utf-8")
                    except:
                        ip = arg
                elif opt in ('-h', '--help'):
                    print("python badip.py --api_key=<API_KEY> --ip=<IP>")
                    return 0
        except getopt.error as msg:
            raise Exception(msg)

        try:
            client = apilityio.Client(api_key=api_key)
            api_key, protocol, host = client.GetConnectionData()

            print('Host: %s' % host)
            print('Protocol: %s' % protocol)
            print('API Key: %s' % api_key)

            print('Badip IP: %s' % ip)

            response = client.CheckIP(ip)

            if response.status_code == 404:
                print("Congratulations! The IP address has not been found in any blacklist.")
                return 0
            if response.status_code != 200:
                print("The API call returned this error HTTP %s: %s" % (response.status_code, response.error))
                return 0

            blacklists = response.blacklists
            print("Ooops! The IP address has been found in one or more blacklist.")
            print('+- Blacklists: %s' % blacklists)


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



