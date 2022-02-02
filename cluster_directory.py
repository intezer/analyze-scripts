import os
import sys

import networkx as nx
import requests
import networkx.readwrite.gexf as gexf

BASE_URL = 'https://analyze.intezer.com/api/v2-0'
API_KEY = 'YOUR API KEY'


def get_session():
    response = requests.post(BASE_URL + '/get-access-token', json={'api_key': API_KEY})
    response.raise_for_status()
    session = requests.session()
    session.headers['Authorization'] = session.headers['Authorization'] = 'Bearer %s' % response.json()['result']
    return session


def send_to_analysis(file_path, session):
    result_url = ''
    with open(file_path, 'rb') as file_to_upload:
        files = {'file': (os.path.basename(file_path), file_to_upload)}
        response = session.post(BASE_URL + '/analyze', files=files)
        if response.status_code == 201 or response.status_code == 200:
            result_url = response.json()['result_url']
        else:
            print('Analyzing of file named {0} failed with code: {1} message: {2} '.format(file_path,
                                                                                           response.status_code,
                                                                                           response.text))
        return result_url


def analyze_directory(dir_path, session):
    result_urls = []
    results = []
    for path in os.listdir(dir_path):
        file_path = os.path.join(dir_path, path)
        if os.path.isfile(file_path):
            result_url = send_to_analysis(file_path, session)
            if result_url:
                result_urls.append((result_url, os.path.basename(path)))

    while result_urls:
        result_url, file_name = result_urls.pop()
        response = session.get(BASE_URL + result_url)
        response.raise_for_status()
        if response.status_code != 200:
            result_urls.append((result_url, file_name))
        else:
            report = response.json()['result']
            if report['verdict'] != 'not_supported':
                results.append((report['sha256'], report['analysis_id'], file_name))

    return results


def send_to_related_samples(analysis_id, session):
    result_url = ''
    response = session.post(BASE_URL + '/analyses/{}/sub-analyses/root/get-account-related-samples'.format(analysis_id))
    if response.status_code != 201:
        print('Get related sampled for analysis ID: {0} failed with status code {1}'.format(analysis_id, response.status_code))
    else:
        result_url = response.json()['result_url']
    return result_url


def get_related_samples(results, session):
    result_urls = []
    previous_samples = {}
    for sha256, analysis_id, file_name in results:
        result_url = send_to_related_samples(analysis_id, session)
        if result_url:
            result_urls.append((sha256, result_url))

    while result_urls:
        sha256, result_url = result_urls.pop()
        response = session.get(BASE_URL + result_url)
        response.raise_for_status()
        if response.status_code != 200:
            result_urls.append((sha256, result_url))
        else:
            previous_samples[sha256] = response.json()['result']['related_samples']

    return previous_samples


def draw_graph(previous_samples):
    g = nx.Graph()
    g.add_nodes_from(previous_samples)

    for sha256, (related_samples) in previous_samples.items():
        for analysis in related_samples:
            if analysis['analysis']['sha256'] in previous_samples:
                g.add_edge(sha256, analysis['analysis']['sha256'], gene_count=analysis['reused_genes']['gene_count'])

    gexf.write_gexf(g, 'output.gexf')
    print('graph was saved as output.gexf')


def main(dir_path):
    session = get_session()
    results = analyze_directory(dir_path, session)
    previous_samples = get_related_samples(results, session)
    draw_graph(previous_samples)


if __name__ == '__main__':
    main(sys.argv[1])
