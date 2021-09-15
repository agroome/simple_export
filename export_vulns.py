import csv
from argparse import ArgumentParser
from datetime import datetime
from time import sleep
from urllib import request
import json
import logging
import re
from pathlib import Path
from typing import List, Iterator

DEFAULT_CHUNK_SIZE = 500
DEFAULT_POLL_INTERVAL = 3
BASE_URL = 'https://cloud.tenable.com'

LOG_DATE_FMT = '%m/%d/%Y %H:%M:%S'
LOG_FMT = '%(asctime)s[%(levelname)s]:%(message)s'
logging.basicConfig(format=LOG_FMT, level=logging.INFO, datefmt=LOG_DATE_FMT)

default_config_path = Path(f'{__file__}').parent
default_config_file = '.env'

date_string = datetime.now().strftime("%m-%d-%Y")
default_output_path = Path(f'{__file__}').parent
default_output_filename = f'vuln_export_{date_string}.csv'

get_headers = {'Accept': 'application/json'}
post_headers = {'Accept': 'application/json', 'Content-type': 'application/json'}
download_headers = {'Accept': 'application/octet-stream'}


def rename_columns(records: Iterator[dict], name_map: dict) -> List[dict]:
    """Using the name_map dictionary, map the column name when an entry matches."""
    for record in records:
        yield {name_map[k]: v for k, v in record.items() if k in name_map}


def read_env_file(filename: str) -> dict:
    """Read a simple environment file that contains api_keys and new column header names.
    :param filename
    :returns: dictionary with keys: 'api_keys' and 'rename_fields'

    #  FILE FORMAT:
    #
    description:
        ACCESS_KEY=9a09bb6a...
        SECRET_KEY=0f262ed9...

    rename_fields:
        asset.ipv4                   : IP
        asset.hostname               : Hostname
        asset.operating_system       : OS
        plugin.name                  : Vulnerability Title
        severity                     : Severity
        plugin.cvss_base_score       : CVSS Score
        plugin.exploit_available     : Exploit Exists? (YES/NO)
        state                        : Vulnerability status (Fixed/Active)
        first_found                  : Date Vuln was detected
        last_fixed                   : Vuln Remediation date
    """
    keys_dict = dict()
    field_dict = dict()
    keys_regex = '^\\s*(?P<token>access_key|secret_key)\\s*=\\s*(?P<value>[0-9a-z]+)\\s*$'
    fields_regex = '^\\s*(?P<original_field>[a-z_.]+)\\s+:\\s+(?P<new_field>[A-Za-z].*)\\s*$'
    try:
        with open(filename) as fobj:
            for line in fobj:

                m = re.match(keys_regex, line, re.IGNORECASE)
                match = m and m.groupdict()
                if match:
                    keys_dict.update({match['token'].lower(): match['value']})

                m = re.match(fields_regex, line, re.IGNORECASE)
                match = m and m.groupdict()
                if match:
                    field_dict.update({match['original_field'].strip(): match['new_field'].strip()})

    except Exception as e:
        SystemExit(repr(e))

    logging.debug(f'rename fields: {field_dict}')
    return {'api_keys': keys_dict, 'rename_columns': field_dict}


class VulnerabilityExportRequest:
    """Prepare a vuln export request. Filters and such can go in the payload"""
    def __init__(self, chunk_size=DEFAULT_CHUNK_SIZE):
        self.num_assets = chunk_size

    @property
    def payload(self):
        return {"num_assets": self.num_assets}


class VulnerabilityExporter:
    """Minimal exporter that uses urllib."""
    poll_interval = DEFAULT_POLL_INTERVAL
    export_url = f'{BASE_URL}/vulns/export'

    def __init__(self, access_key: str, secret_key: str, export_request: VulnerabilityExportRequest = None):
        self.auth_header = {'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}'}
        self.status_url_fmt = f'{self.export_url}/{{export_uuid}}/status'
        self.chunks_url_fmt = f'{self.export_url}/{{export_uuid}}/chunks/{{chunk_id}}'
        self.request = export_request or VulnerabilityExportRequest()

    def _request_export(self):
        logging.debug(f'url: {self.export_url}')
        logging.debug(f'request payload: {self.request.payload}')
        req = request.Request(
            url=self.export_url,
            data=json.dumps(self.request.payload).encode(),
            headers={**self.auth_header, **post_headers})
        return json.load(request.urlopen(req))['export_uuid']

    def _check_status(self, export_uuid):
        status_request = request.Request(
            url=self.status_url_fmt.format(export_uuid=export_uuid),
            headers={**self.auth_header, **get_headers})
        while True:
            response = json.load(request.urlopen(status_request))
            if response['status'] == 'FINISHED':
                break
            sleep(self.poll_interval)
        logging.debug(response['chunks_available'])
        return response

    def _iter_chunk(self, export_uuid, chunk_id):
        chunk_url = self.chunks_url_fmt.format(export_uuid=export_uuid, chunk_id=chunk_id)
        req = request.Request(chunk_url, headers={**self.auth_header, **download_headers})
        chunk = request.urlopen(req)
        records = json.loads(chunk.read().decode())
        for record in records:
            yield record

    def __iter__(self):
        export_uuid = self._request_export()
        response = self._check_status(export_uuid)
        available_chunks = response['chunks_available']
        for chunk_id in available_chunks:
            for chunk in self._iter_chunk(export_uuid, chunk_id):
                yield chunk


def export_to_csv(config_filepath, output_filepath):
    """Read from the export iterator, write csv lines to output_filepath"""
    logging.debug(f'reading config from {config_filepath}')

    config = read_env_file(config_filepath)
    api_keys = config.get('api_keys')
    column_names = config.get('rename_columns')
    logging.debug(f'map column names using {column_names}')

    exporter = VulnerabilityExporter(**api_keys)

    vuln_records = rename_columns(flatten_vuln_export(exporter), name_map=column_names)
    logging.info(f'Exporting records to {output_filepath}.')

    try:
        with open(output_filepath, 'w') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=list(column_names.values()))
            writer.writeheader()
            for count, record in enumerate(vuln_records):
                writer.writerow(record)
            logging.info(f'Exported {count+1} records')
    except Exception as e:
        logging.error(repr(e))
        raise SystemExit(repr(e))


def parse_args():
    """Parse command line arguments."""
    parser = ArgumentParser()
    parser.add_argument('--config-path',
                        help='Location of the config file.',
                        default=default_config_path)
    parser.add_argument('--config-file',
                        help='Name of config file (defaults to .env).',
                        default=default_config_file)
    parser.add_argument('--output-path',
                        help='Path to write output file.',
                        default=default_output_path)
    parser.add_argument('--output-file',
                        help='Output filename (defaults to "vuln_export_{date_string}.csv").',
                        default=default_output_filename)
    return parser.parse_args()


def flatten_vuln_export(records):
    """A generator that will process a list of nested records, yielding a list of flat records"""

    def flatten_dictionary_field(_record, field, recursive=False):
        """ create new fields in _record for each key, value pair in _record[field]
            - prefix the new keys with the name of the dictionary field being processed
            - _record[field] is removed
        """
        new_record = {f'{field}.{k}': v for k, v in _record[field].items()}
        if recursive:
            for k, v in new_record.items():
                if type(v) is dict:
                    new_record = flatten_dictionary_field(new_record, k)
        _record.update(new_record)
        del _record[field]
        return _record

    def process_record(r):
        """Flatten the dictionary columns ('asset', 'plugin', 'scan', 'port')"""
        for field in ('asset', 'plugin', 'scan', 'port'):
            r = flatten_dictionary_field(r, field)
        vpr = r.get('plugin.vpr')
        r['plugin.vpr.score'] = 0.0 if vpr is None else vpr.get('score', 0.0)
        r['asset.operating_system'] = r['asset.operating_system'] and r['asset.operating_system'][0]
        return r

    for record in records:
        yield process_record(record)


def main():
    args = parse_args()
    config_filepath = Path(args.config_path) / args.config_file
    output_filepath = Path(args.output_path) / args.output_file
    return export_to_csv(config_filepath, output_filepath)


if __name__ == '__main__':
    main()
