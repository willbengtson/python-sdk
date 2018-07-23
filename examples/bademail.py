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
            email = None
            options, remainder = getopt.getopt(argv[1:], 'h:a:e', ['help', 'api_key=', 'email='])
            for opt, arg in options:
                if opt in ('-a', '--api_key'):
                    api_key = arg
                if opt in ('-e', '--email'):
                    try:
                        email = unicode(arg, "utf-8")
                    except:
                        email = arg
                elif opt in ('-h', '--help'):
                    print("python bademail.py --api_key=<API_KEY> --email=<DOMAIN>")
                    return 0
        except getopt.error as msg:
            raise Exception(msg)

        try:
            client = apilityio.Client(api_key=api_key)
            api_key, protocol, host = client.GetConnectionData()

            print('Host: %s' % host)
            print('Protocol: %s' % protocol)
            print('API Key: %s' % api_key)

            print('BadEmail EMAIL: %s' % email)

            response = client.CheckEmail(email)

            if response.status_code != 200:
                print("The API call returned this error HTTP %s: %s" % (response.status_code, response.error))
                return 0

            eresponse = response.response
            print('+- Global score: %s' % eresponse.score)
            print('+--- Domain score: %s' % eresponse.domain.score)
            print('+--- Blacklist: %s' % eresponse.domain.blacklist)
            print('+--- Blacklist NS: %s' % eresponse.domain.blacklist_ns)
            print('+--- Blacklist MX: %s' % eresponse.domain.blacklist_mx)
            print('+--- NS: %s' % eresponse.domain.ns)
            print('+--- MX: %s' % eresponse.domain.mx)
            print('+')
            print('+--- Email score: %s' % eresponse.email.score)
            print('+--- Blacklist: %s' % eresponse.email.blacklist)
            print('+')
            print('+--- IP score: %s' % eresponse.ip.score)
            print('+--- Blacklist: %s' % eresponse.ip.blacklist)
            print('+--- Quarantined? %s' % eresponse.ip.is_quarantined)
            print('+--- Address: %s' % eresponse.ip.address)
            print('+')
            print('+--- Source IP score: %s' % eresponse.source_ip.score)
            print('+--- Source Blacklist: %s' % eresponse.source_ip.blacklist)
            print('+--- Source Quarantined? %s' % eresponse.source_ip.is_quarantined)
            print('+--- Source Address: %s' % eresponse.source_ip.address)
            print('+')
            print('+--- Email Address score: %s' % eresponse.address.score)
            print('+--- Email Address Is Role?: %s' % eresponse.address.is_role)
            print('+--- Email Address Is Well Formed?: %s' % eresponse.address.is_well_formed)
            print('+')
            print('+--- SMTP Info score: %s' % eresponse.smtp.score)
            print('+--- SMTP Info exist MX?: %s' % eresponse.smtp.exist_mx)
            print('+--- SMTP Info exist Address?: %s' % eresponse.smtp.exist_address)
            print('+--- SMTP Info Catch All?: %s' % eresponse.smtp.exist_catchall)
            print('+')
            print('+--- Free mail score: %s' % eresponse.freemail.score)
            print('+--- Is Free Email?: %s' % eresponse.freemail.is_freemail)
            print('+')
            print('+--- Disposable Address score: %s' % eresponse.disposable.score)
            print('+--- Is Disposable Address?: %s' % eresponse.disposable.is_disposable)



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



