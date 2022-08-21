import argparse
import base64
import time
import traceback
from typing import List

import jinja2
import pdfkit
from intezer_sdk import api
from intezer_sdk.analysis import FileAnalysis, SubAnalysis


def generate_report(
        sha256: str,
        analysis: FileAnalysis,
        css_input: str,
        template_text: str,
        logo_base64: str,
        save_html_to_file: bool = False):
        
    # Basic info
    analysis_result = analysis.result()
    root_analysis: SubAnalysis = analysis.get_root_analysis()
    family_info = api.get_global_api().get_family_info(
        analysis_result['family_id']) if 'family_id' in analysis_result else {}

    # Handling sub analyses
    sub_analyses: List[SubAnalysis] = analysis.get_sub_analyses()

    # Mapping between source and sub analyses for generating the report
    sub_analysis_by_source = {}

    for sub_analysis in sub_analyses:
        sub_analysis_info = sub_analysis.metadata
        sub_analysis_info['analysis_id'] = sub_analysis.analysis_id

        if sub_analysis.source == 'static_extraction':
            sub_analysis_by_source.setdefault(sub_analysis.source, []).append(sub_analysis_info)
            sub_analysis_info['path'] = sub_analysis.extraction_info['dropped_path']
        elif sub_analysis.source == 'dynamic_execution':
            sub_analysis_by_source.setdefault(sub_analysis.extraction_info['collected_from'], []).append(
                sub_analysis_info)

            if sub_analysis.extraction_info['collected_from'] == 'memory' and sub_analysis.extraction_info.get(
                    'processes'):
                sub_analysis_info['path'] = sub_analysis.extraction_info['processes'][0]['module_path']
                sub_analysis_info['process_id'] = sub_analysis.extraction_info['processes'][0]['process_id']
                sub_analysis_info['parent_process_id'] = sub_analysis.extraction_info['processes'][0][
                    'parent_process_id']

            elif sub_analysis.extraction_info['collected_from'] == 'file_system':
                sub_analysis_info['path'] = sub_analysis.extraction_info['dropped_path']
        else:
            raise Exception(f'Unexpected sub analysis source {sub_analysis.source}')

    # Handling TTPs
    ttps = []
    if analysis.dynamic_ttps:
        severity_map = {1: 'Low', 2: 'Medium', 3: 'High'}
        for ttp in sorted(analysis.dynamic_ttps, key=lambda ttp_: ttp_['severity'], reverse=True):
            ttp_info = {
                'mitre': '-',
                'technique': ttp['description'],
                'severity': severity_map[ttp['severity']],
                'details': '-'
            }

            ttps_text = [f'{list(item.keys())[0]}: {list(item.values())[0]}' for item in ttp['data']]

            if ttps_text:
                ttp_info['details'] = ', '.join(ttps_text)

            if 'ttp' in ttp:
                ttp_info['mitre'] = ttp['ttp']['ttp']

            ttps.append(ttp_info)

    # Arranging the data to send to template
    report_template_data = {
        'now': time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.gmtime()),
        'analyze_base_url': 'https://analyze.intezer.com',
        'logo_base64': logo_base64,
        'indicators_text': ', '.join(ind.get('name') for ind in root_analysis.metadata.get('indicators', []))
    }

    report_template_data.update(analysis_result)
    report_template_data.update(root_analysis.metadata)
    report_template_data.update(family_info)
    report_template_data['sub_analyses'] = sub_analysis_by_source
    report_template_data['ttps'] = ttps
    report_template_data['file_iocs'] = analysis.iocs['files']
    report_template_data['network_iocs'] = analysis.iocs['network']
    report_template_data['css_input'] = css_input

    # Generating the HTML report
    environment = jinja2.Environment()
    template = environment.from_string(template_text)
    html = template.render(**report_template_data)

    if save_html_to_file:
        # Saving HTML file
        with open(f'{sha256}.html', 'w+') as f:
            f.write(html)
            print(f'Saved HTML report to {sha256}.html')

    # Generating PDF file
    pdfkit.from_string(html, f'{sha256}.pdf')
    print(f'Saved PDF report to {sha256}.pdf')


def generate_reports(intezer_apikey, files_sha256):
    api.set_global_api(intezer_apikey)

    css_file_name = 'pdf-report.css'

    with open(css_file_name, mode="r", encoding="utf-8") as css_file:
        css_input = css_file.read()

    with open('pdf-report-tempalte.html', 'r') as f:
        template_text = f.read()

    with open('intezer-logo.png', 'rb') as image_file:
        logo_base64 = base64.b64encode(image_file.read()).decode("utf-8")

    for sha256 in files_sha256:
        try:
            analysis = FileAnalysis.from_latest_hash_analysis(file_hash=sha256)

            if not analysis:
                print(f"Analysis for file hash {sha256} isn't available")

            generate_report(sha256, analysis, css_input, template_text, logo_base64)
        except Exception:
            traceback.print_exc()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generate a PDF and HTML reports for a given Intezer file scan")
    parser.add_argument("-k", "--apikey", help="Intezer API Key", required=True)
    parser.add_argument("-f", "--sha256", help="File hash", required=True)

    args = parser.parse_args()
    generate_reports(args.apikey, [args.sha256])
