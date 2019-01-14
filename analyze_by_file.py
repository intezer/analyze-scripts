import pprint
import sys
import time

import requests

base_url = 'https://analyze.intezer.com/api/v2-0'
api_key = 'YOUR API KEY'


def main(file_path):
    response = requests.post(base_url + '/get-access-token', json={'api_key': api_key})
    response.raise_for_status()
    session = requests.session()
    session.headers['Authorization'] = session.headers['Authorization'] = 'Bearer %s' % response.json()['result']

    with open(file_path, 'rb') as file_to_upload:
        files = {'file': ('file_name', file_to_upload)}
        response = session.post(base_url + '/analyze', files=files)
        assert response.status_code == 201

    while response.status_code != 200:
        time.sleep(1)
        result_url = response.json()['result_url']
        response = session.get(base_url + result_url)
        response.raise_for_status()

    report = response.json()
    pprint.pprint(report)


if __name__ == '__main__':
    main(sys.argv[1])
