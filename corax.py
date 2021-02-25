import click
import requests
import urllib.parse
import base64


@click.group()
def cli():
    pass


@cli.command()
@click.argument('url')
def sanitize(url):
    no_scheme = url.replace('http', 'hxxp')
    no_domains = no_scheme.replace('.', '[.]')
    click.echo('Sanitized URL: ', nl=False)
    click.secho(no_domains, fg='green')


@click.group()
def decode():
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