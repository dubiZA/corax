import re
from urllib import parse as urlparse
import click


class IPAddress(click.ParamType):
    name = 'ip_address'

    def convert(self, value, param, ctx):
        value = value.strip()
        self.rex_ipv4 = (
        r'''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(  
        25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(  
        25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(  
        25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''
        )
        self.rex_ipv6 = (
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
        if not isinstance(value, tuple):
            if not re.match(self.rex_ipv4, value):
                if not re.match(self.rex_ipv6, value):
                    self.fail(
                        f'Invalid IP address ({value}). Use standard IP v4 or v6 formatting.',
                        param,
                        ctx
                    )

        return value


class URL(click.ParamType):
    name = 'url'

    def convert(self, value, param, ctx):
        if not isinstance(value, tuple):
            value = value.strip()
            value = urlparse.urlparse(value)
            if value.scheme not in ('http', 'https'):
                self.fail(
                    f'Invalid URL scheme ({value.scheme}). Only HTTP(S) allowed',
                    param,
                    ctx
                )

        return value


class EmailAddress(click.ParamType):
    name = 'email_address'

    def convert(self, value, param, ctx):
        value = value.strip()
        self.rex_email = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
        if not isinstance(value, tuple):
            if not re.match(self.rex_email, value):
                self.fail(
                    f'Invalid email address ({value}). Make sure it matches <identity>@<domain>.<tld>',
                    param,
                    ctx
                )

        return value