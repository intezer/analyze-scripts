import argparse
import base64
import time
import traceback
from datetime import datetime

import jinja2
import pdfkit
from intezer_sdk import api
from intezer_sdk.base_analysis import Analysis
from intezer_sdk.endpoint_analysis import EndpointAnalysis


def format_analysis_time(scan_start: str, scan_end: str):
    date_format = "%a, %d %b %Y %H:%M:%S %Z"
    # Calculating the time the endpoint scan took
    start_date = datetime.strptime(scan_start, date_format)
    end_date = datetime.strptime(scan_end, date_format)
    calc_scan_time = end_date - start_date
    # Setting the time format
    hours = calc_scan_time.seconds // 3600
    minutes = (calc_scan_time.seconds % 3600) // 60
    seconds = calc_scan_time.seconds % 60

    formatted_time = ""
    if hours > 0:
        formatted_time += f"{hours} hour{'s' if hours > 1 else ''},"
    if minutes > 0:
        formatted_time += f" {minutes} minute{'s' if minutes > 1 else ''} and "

    formatted_time += f"{seconds} second{'s' if seconds > 1 else ''}"
    return formatted_time


def generate_report(
        ep_analysis: Analysis,
        css_input: str,
        template_text: str,
        logo_base64: str,
        save_html_to_file: bool = False):

    all_sub_analyses = ep_analysis.get_sub_analyses()
    sub_analyses = [sub_analysis for sub_analysis in all_sub_analyses if sub_analysis.verdict == 'malicious']

    if not sub_analyses:
        sub_analyses = [sub_analysis for sub_analysis in all_sub_analyses if
                        sub_analysis.verdict in ("suspicious", "unknown")]
        sub_analyses.sort(key=lambda value: value.verdict)
        sub_analyses = sub_analyses[:100]

    family_info = []
    for analysis in sub_analyses:
        if analysis.verdict != 'malicious':
            continue

        if analysis.code_reuse is not None:
            # getting the malicious family name
            malware_families = [
                family
                for family in
                sorted(analysis.code_reuse.get('families', []), key=lambda family_: family_.get('reused_gene_count'),
                       reverse=True)
                if family.get('family_type') == 'malware']

            if malware_families:
                family_info.append({
                    'family_name': malware_families[0].get('family_name'),
                    'family_id': malware_families[0].get('family_id')
                })

    # Basic info
    ep_analysis_metadata = ep_analysis.result()
    ep_analysis_metadata['status'] = ep_analysis.status.value

    ep_analysis_metadata['calc_scan_time'] = format_analysis_time(ep_analysis_metadata['scan_start_time'],
                                                                  ep_analysis_metadata['scan_end_time'])

    if ep_analysis_metadata['families'] is not None and len(ep_analysis_metadata['families']) > 0:
        if len(ep_analysis_metadata['families']) > 1:
            ep_analysis_metadata['families'] = ', '.join(ep_analysis_metadata['families'])
        else:
            ep_analysis_metadata['families'] = ep_analysis_metadata['families'][0]

    sub_analyses_original_names = {}
    for analysis in sub_analyses:
        sub_analysis_metadata = analysis.metadata
        if sub_analysis_metadata.get('original_filename'):
            sub_analyses_original_names[analysis.analysis_id] = sub_analysis_metadata['original_filename']

    report_template_data = {"sub_analyses": sub_analyses,
                            "sub_analyses_original_names": sub_analyses_original_names,
                            "family_info": family_info,
                            "ep_analysis_metadata": ep_analysis_metadata,
                            "sub_analyses_count": len(all_sub_analyses),
                            "logo_base64": logo_base64,
                            "css_input": css_input,
                            "now": time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.gmtime()),
                            "analyze_base_url": "https://analyze.intezer.com"}

    environment = jinja2.Environment()
    template = environment.from_string(template_text)

    html = template.render(**report_template_data)

    analysis_id = ep_analysis.analysis_id
    if save_html_to_file:
        # Saving HTML file
        with open(f'{analysis_id}.html', 'w+') as f:
            f.write(html)
            print(f'Saved HTML report to {analysis_id}.html')

    # Generating PDF file
    pdfkit.from_string(html, f'{analysis_id}.pdf')
    print(f'Saved PDF report to {analysis_id}.pdf')


def generate_reports(intezer_apikey, ep_analyses_ids):
    api.set_global_api(intezer_apikey)

    css_file_name = 'pdf-report.css'

    with open(css_file_name, mode="r", encoding="utf-8") as css_file:
        css_input = css_file.read()

    with open('report_template.html', 'r') as f:
        template_text = f.read()

    with open('intezer-logo.png', 'rb') as image_file:
        logo_base64 = base64.b64encode(image_file.read()).decode("utf-8")
    for ep_analysis_id in ep_analyses_ids:
        try:
            ep_analysis_obj = EndpointAnalysis.from_analysis_id(ep_analysis_id)
            if not ep_analysis_obj:
                print(f"Analysis for endpoint analysis ID: {ep_analysis_id} isn't available")

            generate_report(ep_analysis_obj, css_input, template_text, logo_base64)
        except Exception:
            traceback.print_exc()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generate a PDF and HTML reports for a given Intezer file scan")
    parser.add_argument("-k", "--apikey", help="Intezer API Key", required=True)
    parser.add_argument("-s", "--analysisid", help="Endpoint Analysis IDs", required=True, nargs='+')

    args = parser.parse_args()
    generate_reports(args.apikey, args.analysisid)
