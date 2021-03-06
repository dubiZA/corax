import base64
from ipaddress import IPv4Address
import os
import re
import shutil
import urllib.parse

import click
import requests
import yaml

import validators


# App config vars
app_name = 'corax'
config_file = 'config.yaml'
config_path = click.get_app_dir(app_name)
config_filepath = f'{config_path}/{config_file}'

# Set up rex objects
rex_ipv4 = (
    r'''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(  
    25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(  
    25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(  
    25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''
)
rex_ipv6 = (
    r'''(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}| 
    ([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:) 
    {1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1 
    ,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4} 
    :){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{ 
    1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA 
    -F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a 
    -fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0 
    -9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0, 
    4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1} 
    :){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9 
    ])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0 
    -9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4] 
    |1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4] 
    |1{0,1}[0-9]){0,1}[0-9]))'''
)
rex_url = r'(?:[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]\.){1,127}[a-z]{2,63}'
rex_email = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'


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
            click.secho(f'{config_filepath} does not exist. Creating filepath...', fg='yellow')
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
    no_scheme = url.replace('http', 'hxxp')
    no_domains = no_scheme.replace('.', '[.]')
    click.echo('Sanitized URL: ', nl=False)
    click.secho(no_domains, fg='green')


# Add command for expanding URL shortener URLs
@cli.command('unshorten')
@click.argument('short_url', type=validators.URL())
def unshorten(short_url):
    """Expands URL shortener URLs.

    API limit of 10 requests/hour for novel URLs,
    however, previously unshortened URLs have no
    API limit.
    """
    response = requests.get(f'https://unshorten.me/json/{short_url}')
    resolved_url = response.json()['resolved_url']
    usage_count = response.json()['usage_count']
    click.echo('Unshortened URL: ', nl=False)
    click.secho(resolved_url, fg='green')
    if usage_count > 0:
        click.secho(f'Current usage: {usage_count}. Cannot exceed 10/hour')
    elif usage_count >= 7:
        click.secho(f'WARNING: Usage count at {usage_count}', fg='yellow')
    elif usage_count > 10:
        click.secho(f'Usage count at {usage_count}. Usage Exceeded. Wait 60 minutes', fg='red')


# Add command and logic for checking reputation of various observable types
@click.group()
def reputation():
    """Checks reputation of various observable types"""
    pass


cli.add_command(reputation)

@reputation.command('ip')
@click.argument('ip_address', type=validators.IPAddress())
def rep_ip(ip_address):
    pass


# @cli.command()
# @click.option('--ip', type=validators.IPAddress())
# @click.option('--url', type=validators.URL())
# @click.option('--email', type=validators.EmailAddress())
# def reputation(**kwargs):
#     """Checks reputation of user provided obervables."""
#     #TODO: Add some type of check for hashes and files
#     # observable = observable.strip()
#     # with open(config_filepath, 'r') as config_file:
#     #     data = yaml.load(config_file, Loader=yaml.FullLoader)
#     # vt_key = data['VIRUSTOTAL']
#     # vt_base_url = 'https://www.virustotal.com/api/v3'
#     # vt_header = {'x-apikey': vt_key}

#     # if re.match(rex_ipv4, observable):
#     #     print(IPv4Address(observable).is_global)
#     #     if IPv4Address(observable).is_global:
#     #         response = requests.get(
#     #             f'{vt_base_url}/ip_addresses/{observable}',
#     #             headers=vt_header
#     #         )
#     #         print(response.json()['data']['attributes']['reputation'])
#     # elif re.match(rex_ipv6, observable):
#     #     print('ipv6')
#     # elif re.match(rex_email, observable):
#     #     print('email')
#     # elif re.search(rex_url,observable):
#     #     print('url')
#     # else:
#     #     click.secho(
#     #         'Invalid observable type. IP, email or URL only.',
#     #         fg='yellow'
#     #         )
#     print('oh yeah')


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
        'urls': [url]
    }
    response = requests.post(
        'https://tap-api-v2.proofpoint.com/v2/url/decode',
        json=encoded_url
        )
    click.echo('Proofpointed Decoded URL: ', nl=False)
    click.secho(response.json()['urls'][0]['decodedUrl'], fg='green')


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


