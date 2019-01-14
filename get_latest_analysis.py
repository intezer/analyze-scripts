import pprint
import sys

import requests

base_url = 'https://analyze.intezer.com/api/v2-0'
api_key = 'YOUR API KEY'


def main(hash_value):
    response = requests.post(base_url + '/get-access-token', json={'api_key': api_key})
    response.raise_for_status()
    session = requests.session()
    session.headers['Authorization'] = session.headers['Authorization'] = 'Bearer %s' % response.json()['result']

    response = session.get(base_url + '/files/{}'.format(hash_value))
    if response.status_code == 404:
        print('File not found')
        return

    response.raise_for_status()

    report = response.json()
    pprint.pprint(report)


if __name__ == '__main__':
    main(sys.argv[1])
