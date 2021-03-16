FROM python:3.9.2-alpine
RUN mkdir /corax
WORKDIR /corax
COPY . /corax/
CMD pip install .