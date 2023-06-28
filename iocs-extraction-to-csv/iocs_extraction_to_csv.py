from intezer_sdk import api
from intezer_sdk.analysis import FileAnalysis
import argparse
import requests
from intezer_sdk.analyses_history import query_file_analyses_history
from datetime import datetime
import csv


def write_to_csv(data, filename):
    with open(filename, 'w', encoding='utf-8', errors='surrogateescape') as csvfile:
        fieldnames = ['Type', 'IOC', 'Verdict', 'Family', 'Analysis URL']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        rows = []
        for item in data:
            row = {
                'Type': item['type'],
                'IOC': item['ioc'] if item.get('source') is not None and 'file' not in item.get('source') else item[
                    'path'],
                'Verdict': item['verdict'] if item.get('verdict') is not None else 'N/A',
                'Family': item['family'] if item.get('family') is not None else 'N/A',
                'Analysis URL': item['analysis_url']
            }
            rows.append(row)

        writer.writerows(rows)
    print(f'Saved CSV: {filename} to directory')


def ioc_extraction(start_date: datetime, end_date: datetime):
    history_results = query_file_analyses_history(start_date=start_date, end_date=end_date, aggregated_view=True)
    files_ios_list = []
    for analysis in history_results:
        analysis = FileAnalysis.from_analysis_id(analysis['analysis_id'])

        url = analysis.result()['analysis_url']
        if analysis.iocs:
            if analysis.iocs['network']:
                files_ios_list.extend([
                    {**ioc, 'analysis_url': url}
                    for ioc in analysis.iocs['network']
                ])
    
            if analysis.iocs['files']:
                files_ios_list.extend([
                    {**ioc, 'analysis_url': url}
                    for ioc in analysis.iocs['files']
                ])
    if len(history_results) == 0:
        print('No data to show in the chosen timeframe')
        exit()
    files_ios_list = sorted(files_ios_list, key=lambda item: (item['type'], item['analysis_url']))
    filename = 'extracted_iocs.csv'

    write_to_csv(files_ios_list, filename)


def date_conversion(intezer_api_key, start_date_str: str, end_date_str: str = None):
    api.set_global_api(intezer_api_key)
    try:
        # Convert the date string to a datetime object
        if end_date_str is None:
            end_date = datetime.now()
        else:
            end_date = datetime.fromisoformat(end_date_str)
        start_date = datetime.fromisoformat(start_date_str)

        ioc_extraction(start_date, end_date)
    except ValueError as error:
        print(f'ValueError: {error}')
    except requests.exceptions.HTTPError as error:
        print(f'HTTPError: {error}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extracting IOCs of all Intezer analysis from a given '
                                                 'time frame or start date')
    parser.add_argument('-k', '--api-key', help='Intezer API Key', required=True)
    parser.add_argument('-s', '--start-date', help='History start date, YYYY-MM-DD', required=True)
    parser.add_argument('-e', '--end-date', help='History end date, YYYY-MM-DD, default: Today', required=False)

    args = parser.parse_args()
    date_conversion(args.api_key, args.start_date, args.end_date)
