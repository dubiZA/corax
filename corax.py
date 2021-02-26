import base64
import os
import urllib.parse
import click
import requests


APP_NAME = 'corax'
CONFIG_FILE = 'config.yaml'
CONFIG_PATH = click.get_app_dir(APP_NAME)

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
@click.option('--virustotal', '-v', help='VirusTotal API key.')
@click.option('--abuseip', '-a', help='AbuseIPDB API key.')
@click.option('--urlscan', '-u', help='URLScan.io API key.')
@click.option('--hibp', '-h', help='HaveIBeenPwned API key.')
@click.option('--emailrep', '-e', help='EmailRep.io API key.')
def configure_corax(**kwargs):
    """Configure corax.

    Several corax utilities require API keys or
    other configurations to function correctly. Invoking
    corax config enables configurations to be set.
    """
    if kwargs['virustotal']:
        pass
    elif kwargs['abuseip']:
        pass
    elif kwargs['urlscan']:
        pass
    elif kwargs['hibp']:
        pass
    elif kwargs['emailrep']:
        pass
    else:
        if not os.path.isfile(f'{CONFIG_PATH}/{CONFIG_FILE}'):
            click.secho(f'{CONFIG_PATH}/{CONFIG_FILE} does not exist. Creating filepath...', fg='yellow')
            os.mkdir(CONFIG_PATH)
            with open(f'{CONFIG_PATH}/{CONFIG_FILE}', 'a') as writer:
                writer.writelines('Hello, World!')
                #TODO: Complete writing the initial config file and then open to edit
        #TODO: Add else statement to open config file if it does indeed exist already



# Add command for sanitizing URLs
@cli.command()
@click.argument('url')
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
@click.argument('short_url')
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
@click.argument('url')
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
@click.argument('url')
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


