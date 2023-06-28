import argparse
import base64
import time
import traceback
from datetime import datetime

import jinja2
import pdfkit
from intezer_sdk import api
from intezer_sdk.endpoint_analysis import EndpointAnalysis


def scan_duration(scan_start: str, scan_end: str):
    date_format = '%a, %d %b %Y %H:%M:%S %Z'
    # Calculating the time the endpoint scan took
    start_date = datetime.strptime(scan_start, date_format)
    end_date = datetime.strptime(scan_end, date_format)
    calc_scan_time = end_date - start_date
    # Setting the time format
    duration_in_seconds = int(calc_scan_time.total_seconds())
    hours = duration_in_seconds // 3600
    minutes = (duration_in_seconds % 3600) // 60
    seconds = duration_in_seconds % 60

    formatted_time = ''
    if hours > 0:
        formatted_time += f"{hours} hour{'s' if hours > 1 else ''},"
    if minutes > 0:
        formatted_time += f" {minutes} minute{'s' if minutes > 1 else ''} and "

    formatted_time += f"{seconds} second{'s' if seconds > 1 else ''}"
    return formatted_time


def generate_report(
        endpoint_analysis: EndpointAnalysis,
        css_input: str,
        template_text: str,
        logo_base64: str,
        save_html_to_file: bool = False):
    all_sub_analyses = endpoint_analysis.get_sub_analyses()
    sub_analyses = [sub_analysis for sub_analysis in all_sub_analyses if sub_analysis.verdict == 'malicious']

    if not sub_analyses:
        sub_analyses = [sub_analysis for sub_analysis in all_sub_analyses if
                        sub_analysis.verdict in ('suspicious', 'unknown')]
        sub_analyses.sort(key=lambda value: (value.verdict != 'suspicious', value.verdict))
        sub_analyses = sub_analyses[:100]

    family_info = []
    for analysis in sub_analyses:
        if analysis.verdict != 'malicious':
            continue

        if analysis.code_reuse:
            # Getting the malicious family name
            malware_families = []
            families = sorted(analysis.code_reuse.get('families', []),
                              key=lambda family_: family_.get('reused_gene_count'), reverse=True)

            for family in families:
                if family.get('family_type') == 'malware':
                    malware_families.append(family)

            if malware_families:
                family_info.append({
                    'family_name': malware_families[0].get('family_name'),
                    'family_id': malware_families[0].get('family_id')
                })

    # Basic info
    endpoint_analysis_metadata = endpoint_analysis.result()
    endpoint_analysis_metadata['status'] = endpoint_analysis.status.value

    endpoint_analysis_metadata['calc_scan_time'] = scan_duration(endpoint_analysis_metadata['scan_start_time'],
                                                                 endpoint_analysis_metadata['scan_end_time'])

    if endpoint_analysis_metadata['families']:
        endpoint_analysis_metadata['families'] = ', '.join(endpoint_analysis_metadata['families'])

    sub_analyses_original_names = {}
    for analysis in sub_analyses:
        sub_analysis_metadata = analysis.metadata
        if sub_analysis_metadata.get('original_filename'):
            sub_analyses_original_names[analysis.analysis_id] = sub_analysis_metadata['original_filename']

    report_template_data = {'sub_analyses': sub_analyses,
                            'sub_analyses_original_names': sub_analyses_original_names,
                            'family_info': family_info,
                            'endpoint_analysis_metadata': endpoint_analysis_metadata,
                            'sub_analyses_count': len(all_sub_analyses),
                            'logo_base64': logo_base64,
                            'css_input': css_input,
                            'now': time.strftime('%a, %d %b %Y %H:%M:%S %Z', time.gmtime()),
                            'analyze_base_url': 'https://analyze.intezer.com'}

    environment = jinja2.Environment(autoescape=True)
    template = environment.from_string(template_text)

    html = template.render(**report_template_data)

    analysis_id = endpoint_analysis.analysis_id
    if save_html_to_file:
        # Saving HTML file
        with open(f'{analysis_id}.html', 'w+') as f:
            f.write(html)
            print(f'Saved HTML report to {analysis_id}.html')

    # Generating PDF file
    pdfkit.from_string(html, f'{analysis_id}.pdf')
    print(f'Saved PDF report to {analysis_id}.pdf')


def generate_reports(intezer_apikey, endpoint_analyses_ids):
    api.set_global_api(intezer_apikey)

    css_file_name = 'endpoint_analysis_pdf_report.css'

    with open(css_file_name, mode='r') as css_file:
        css_input = css_file.read()

    with open('report_template.html', 'r') as f:
        template_text = f.read()

    with open('intezer-logo.png', 'rb') as image_file:
        logo_base64 = base64.b64encode(image_file.read()).decode('utf-8')
    for endpoint_analysis_id in endpoint_analyses_ids:
        try:
            endpoint_analysis_obj = EndpointAnalysis.from_analysis_id(endpoint_analysis_id)
            if not endpoint_analysis_obj:
                print(f"Analysis for endpoint analysis ID: {endpoint_analysis_id} isn't available")

            generate_report(endpoint_analysis_obj, css_input, template_text, logo_base64)
        except Exception:
            traceback.print_exc()


if __name__ == '__main__':
    generate_reports('2ce26e8a-f658-4aa2-878e-9e2f2867bbfe', ['5e32dd43-19fd-407c-90b1-5393ec1fd05b',
                                                              '4c32d2fd-90a3-472d-80cb-ca2649400fce',
                                                              '04e50e3e-c57e-42fb-ae8b-b2145f74aa49',
                                                              'e707207b-1ebb-400d-a06a-233d159e78e5',
                                                              '0cc05690-4203-4ce8-857d-d3a8caca753f',
                                                              '3d6dd2e8-9496-41ba-bc19-8f5a1ad35549',
                                                              '5600455a-d0ff-47de-afed-fe6f8dbb249b',
                                                              'e604d686-4aaa-4413-b650-822babd45410',
                                                              '9092b2f2-d4a5-4bc4-8440-3f7bfde4cdee',
                                                              '3aa78c09-775e-432b-a7e0-f3b33caca646',
                                                              '2a4e9def-505a-4274-8aed-946a876667ba',
                                                              'edf73e19-22a9-4eac-89a2-56bdfe7b080b',
                                                              '2dd439d7-45bb-4bf2-a65f-05f24ac4296c',
                                                              '555501e5-baca-46f7-b5da-1d63d0ed57f9',
                                                              '825b00d9-4503-40c2-a090-7f9f65fafb94',
                                                              'ebf39060-e6c0-4fec-b7d2-4cd21c418ac4',
                                                              '202872e7-b62c-4790-9bce-baf249f219de',
                                                              '200a4f9f-a541-4a99-bfbe-c9ce0522c012',
                                                              'f717c962-f6b0-4dd5-8339-a1657824b103'])
    exit()
    parser = argparse.ArgumentParser(description='Generate a PDF and HTML reports for a given Intezer file scan')
    parser.add_argument('-k', '--api-key', help='Intezer API Key', required=True)
    parser.add_argument('-a', '--analysis-id', help='Endpoint Analysis IDs', required=True, nargs='+')

    args = parser.parse_args()
    generate_reports(args.api_key, args.analysis_id)
