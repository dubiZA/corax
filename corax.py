import base64
import urllib.parse
import click
import requests


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
def decode_unshorten(short_url):
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
        click.secho(f'WARNING: Usage count at {usage_count}', fg='orange')
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



