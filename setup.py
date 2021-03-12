from setuptools import setup

setup(
    name='corax',
    version='0.0.1',
    py_modules=['corax'],
    install_requires=[
        'click',
        'requests',
        'pyyaml',
        'tldextract'
    ],
    entry_points='''
        [console_scripts]
        corax=corax:cli
    ''',
)
