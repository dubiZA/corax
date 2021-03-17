# corax

## Python Quick Start
To install corax, follow these steps:
1. Clone the repo locally `git clone https://github.com/dubiZA/corax.git`
2. Change directories to corax root directory
3. Create a Python 3 virtual environment: `python3 -m venv .venv`
4. Activate the virtaul env: `source ./.venv/bin/activate`
5. Install corax `pip3 install .`
6. Configure corax `corax config` if you have API keys to supported services (only VirusTotal with limited functionality at present) 
7. Start using. Run `corax --help` for a list of commands/subcommands

## Docker Quick Start
To run corax in Docker, follow these steps:
1. Clone the repo locally `git clone https://github.com/dubiZA/corax.git`
2. Change directories to corax root directory
3. Run `docker build -t corax --rm .`
4. Run `docker run -it --name corax --rm --mount type=bind,source="$(pwd)"/config,target=/root/.config/corax corax`
5. Configure corax `corax config` if you have API keys to supported services (only VirusTotal with limited functionality at present)
6. Start using. Run `corax --help` for a list of commands/subcommands
