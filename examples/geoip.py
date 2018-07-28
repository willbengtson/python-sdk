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
            options, remainder = getopt.getopt(
                argv[1:], 'h:a:i', ['help', 'api_key=', 'ip='])
            for opt, arg in options:
                if opt in ('-a', '--api_key'):
                    api_key = arg
                if opt in ('-i', '--ip'):
                    try:
                        ip = unicode(arg, "utf-8")
                    except:
                        ip = arg
                elif opt in ('-h', '--help'):
                    print("python geoip.py --api_key=<API_KEY> --ip=<IP>")
                    return 0
        except getopt.error as msg:
            raise Exception(msg)

        try:
            client = apilityio.Client(api_key=api_key)
            api_key, protocol, host = client.GetConnectionData()

            print('Host: %s' % host)
            print('Protocol: %s' % protocol)
            print('API Key: %s' % api_key)

            print('Geolocate IP: %s' % ip)

            response = client.GetGeoIP(ip)
            if response.status_code != 200:
                print("The API call returned this error HTTP %s: %s" %
                      (response.status_code, response.error))
                return 0

            geoip = response.geoip
            print('+- Accuracy radius: %s' % geoip.accuracy_radius)
            print('+- Address: %s' % geoip.address)
            print('+- City: %s' % geoip.city)
            print('+- City Geoname ID: %s' % geoip.city_geoname_id)
            print('+- City Names: %s' % geoip.city_names)
            print('+- Continent: %s' % geoip.continent)
            print('+- Continent Geo Name ID: %s' % geoip.continent_geoname_id)
            print('+- Continent Names: %s' % geoip.continent_names)
            print('+- Country: %s' % geoip.country)
            print('+- Country Geo Name ID: %s' % geoip.country_geoname_id)
            print('+- Country Names: %s' % geoip.country_names)
            print('+- Hostname: %s' % geoip.hostname)
            print('+- Latitude: %s' % geoip.latitude)
            print('+- Longitude: %s' % geoip.longitude)
            print('+- Postal code: %s' % geoip.postal)
            print('+- Region: %s' % geoip.region)
            print('+- Region Geoname ID: %s' % geoip.region_geoname_id)
            print('+- Region Names: %s' % geoip.region_names)
            print('+- Time Zone: %s' % geoip.time_zone)
            print('+--- AS number: %s' % geoip.asystem.asn)
            print('+--- AS name: %s' % geoip.asystem.name)
            print('+--- AS country: %s' % geoip.asystem.country)
            print('+--- AS networks: %s' % geoip.asystem.networks)

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
