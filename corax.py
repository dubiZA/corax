import click
import requests


def decoder_proofpoint(url):
    encoded_url = {
        'urls': [url]
    }

    response = requests.post('https://tap-api-v2.proofpoint.com/v2/url/decode',
                                json=encoded_url)
    
    return response.json()['urls'][0]['decodedUrl']


def sanitize_url(url):
    no_scheme = url.replace('http', 'hxxp')
    no_domains = no_scheme.replace('.', '[.]')

    return no_domains


@click.command()
@click.argument('input')
def cli(input):
    if 'https://urldefense.' in input:
        decoder_proofpoint(input)
        click.secho(f'\n{decoder_proofpoint(input)}', fg='green')
    elif 'https://' in input or 'http://' in input:
        click.secho(f'\n{sanitize_url(input)}', fg='green')
