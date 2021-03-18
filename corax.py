import base64
from ipaddress import IPv4Address
import json
import os
import re
import shutil
import time
import urllib.parse

import click
import requests
import tldextract
import yaml

import validators


# App config vars
app_name = 'corax'
config_file = 'config.yaml'
config_path = click.get_app_dir(app_name)
config_filepath = f'{config_path}/{config_file}'

# Create the toplevel command group
@click.group()
@click.version_option()
def cli():
    """A SOC Analyst Command Line Tool.

    corax is a CLI tool aimed at helping SOC Analysts
    quickly get information they need about
    observables and other artifacts related to
    triaging and investigating secuirty events and
    alerts.
    """
    pass


# Add command to allow configuration of corax
@cli.command('config')
def configure_corax():
    """Configure corax.

    Several corax utilities require API keys or
    other configurations to function correctly. Invoking
    corax config enables configurations to be set.
    """
    if not os.path.isfile(config_filepath):
        click.secho(f'{config_filepath} does not exist. Creating...', fg='yellow')
        if not os.path.isdir(config_path):
            os.mkdir(config_path)
        example_config_filepath = f'{os.getcwd()}/{config_file}'
        if os.path.isfile(example_config_filepath):
            shutil.copy(example_config_filepath, config_filepath)
    
    click.edit(filename=config_filepath)


# Add command for sanitizing URLs
@cli.command()
@click.argument('url', type=validators.URL())
def sanitize(url):
    """Sanitizes provided URLs.

    Provide a URL as the command argument and
    corax will rewrite the string in a format
    safe for use in applications that auto create
    hyperlinks from URLS (email and IM clients, etc.)
    """
    url = url.geturl()
    no_scheme = url.replace('http', 'hxxp')
    no_domains = no_scheme.replace('.', '[.]')
    result = {
        'original_url': url,
        'sanitized_url': no_domains
    }
    click.echo_via_pager(json.dumps(result, indent=4))


# Add command for expanding URL shortener URLs
@cli.command('unshorten')
@click.argument('short_url', type=validators.URL())
def unshorten(short_url):
    """Expands URL shortener URLs.

    API limit of 10 requests/hour for novel URLs,
    however, previously unshortened URLs have no
    API limit.
    """
    response = requests.get(f'https://unshorten.me/json/{short_url.geturl()}')
    click.echo_via_pager(json.dumps(response.json(), indent=4))


# Add command and logic for checking reputation of various observable types
@click.group()
def analyze():
    """Checks reputation of various observable types."""
    pass


cli.add_command(analyze)

@analyze.command('ip')
@click.argument('ip_address', type=validators.IPAddress())
def analyze_ip(ip_address):
    with open(config_filepath, 'r') as config:
        api_keys = yaml.safe_load(config)

    vt_headers = {'x-apikey': api_keys['VIRUSTOTAL']}
    vt_response = requests.get(
        f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}',
        headers=vt_headers
    )
    vt_response = vt_response.json()['data']['attributes']

    analysis_results = {
        'whois_summary': {
            'asn': vt_response['asn'],
            'as_owner': vt_response['as_owner'],
            'regional_internet_registry': vt_response['regional_internet_registry'],
            'network_cidr': vt_response['network'] ,
            'country': vt_response['country'],
        },
        'virus_total_summary': {
            'reputation': vt_response['reputation'],
            'community_votes': {
                'harmless': vt_response['total_votes']['harmless'],
                'malicious': vt_response['total_votes']['malicious'],
            },
            'last_analysis_stats': vt_response['last_analysis_stats'],
            'vt_gui_link': f'https://www.virustotal.com/gui/ip-address/{ip_address}/detection',
        },
    }

    click.echo_via_pager(json.dumps(analysis_results, indent=4))


@analyze.command('email')
@click.argument('email_address', type=validators.EmailAddress())
def analyze_email(email_address):
    pass


@analyze.command('url')
@click.argument('url', type=validators.URL())
def analyze_url(url):
    with open(config_filepath, 'r') as config:
        api_keys = yaml.safe_load(config)
        
    unparsed_url = url.geturl()
    fqdn = url.netloc
    pqdn = tldextract.extract(fqdn).registered_domain

    #TODO: Analyze URL with VT
    encoded_url = base64.urlsafe_b64encode(unparsed_url.encode()).decode().strip('=')
    vt_headers = {'x-apikey': api_keys['VIRUSTOTAL']}
    vt_response = requests.get(
        f'https://www.virustotal.com/api/v3/urls/{encoded_url}',
        headers=vt_headers
    )
    # print(json.dumps(vt_response.json(), indent=4))

    if 'error' in vt_response.json():
        payload = {'url': unparsed_url}
        vt_analysis = requests.post(
            f'https://www.virustotal.com/api/v3/urls',
            headers=vt_headers,
            data=payload
        )
        # Pause execution to allow VT to complete analysis
        click.secho('Waiting for VirusTotal to complete Analysis', fg='yellow')
        time.sleep(15)

        vt_url_search = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{encoded_url}',
            headers=vt_headers
        )
        # print(json.dumps(vt_results.json(), indent=4))

    vt_response = vt_response.json()['data']['attributes']
    vt_results = {
        'last_final_url': vt_response['last_final_url'],
        'last_http_response_code': vt_response['last_http_response_code'] if 'last_http_response_code' in vt_response else '',
        'last_analysis_stats': vt_response['last_analysis_stats'],
        'threat_names': vt_response['threat_names'],
        'reputation': vt_response['reputation'],
        'total_votes': vt_response['total_votes'],
        'times_submitted': vt_response['times_submitted'],
        'outgoing_links': vt_response['outgoing_links'] if 'outgoing_links' in vt_response else '',
        'vt_gui_link': f'https://www.virustotal.com/gui/url/{encoded_url}/detection'
    }

    click.echo_via_pager(json.dumps(vt_results, indent=4))
        # Stuff to pull out:
        # -Outgoing Links
        # -Last Analysis Stats
        # -Last Finaly URL
        # -Last HTTP response code
        # -Reputation
        # -Categories
        # -Times Submitted
        # -Total Votes
        # -
        # -
        # -
    # 
    #TODO: Analyze URL with URLScan.io
    #TODO: Analyze domain
    #TODO: Analyze IP

    #TODO: Build report and return it
    # rep_results = {
    #     'whois_summary': {
    #         'asn': vt_response['asn'],
    #         'as_owner': vt_response['as_owner'],
    #         'regional_internet_registry': vt_response['regional_internet_registry'],
    #         'network_cidr': vt_response['network'] ,
    #         'country': vt_response['country'],
    #     },
    #     'virus_total_summary': {
    #         'reputation': vt_response['reputation'],
    #         'community_votes': {
    #             'harmless': vt_response['total_votes']['harmless'],
    #             'malicious': vt_response['total_votes']['malicious'],
    #         },
    #         'last_analysis_stats': vt_response['last_analysis_stats'],
    #         'gui_link': f'https://www.virustotal.com/gui/ip-address/{ip_address}/detection',
    #     },
    # }
    # print(vt_response.json())
    # click.echo_via_pager(json.dumps(vt_response.json(), indent=4))


# Add decoder command group with subcommands
@click.group()
def decode():
    """Parent command for actioning decode operations.

    corax can be used to decode multiple types of
    encoding schemes like Proofpoint TAP encoded
    URLs, base64 encoded strings, URL encoding, etc.
    """
    pass


cli.add_command(decode)

@decode.command('proofpoint')
@click.argument('url', type=validators.URL())
def decode_proofpoint(url):
    encoded_url = {
        'urls': [url.geturl()]
    }
    response = requests.post(
        'https://tap-api-v2.proofpoint.com/v2/url/decode',
        json=encoded_url
        )
    click.echo_via_pager(json.dumps(response.json(), indent=4))


@decode.command('url')
@click.argument('url', type=validators.URL())
def decode_url(url):
    decoded_url = urllib.parse.unquote_plus(url)
    click.echo('Decoded URL: ', nl=False)
    click.secho(decoded_url, fg='green')


@decode.command('base64')
@click.argument('base64_string')
def decode_base64(base64_string):
    decoded_base64 = str(base64.b64decode(base64_string), 'utf-8')
    click.echo('Decoded String: ', nl=False)
    click.secho(decoded_base64, fg='green')