FROM python:3.9.2-alpine

RUN apk update && apk upgrade && apk add bash && mkdir /corax && mkdir -p /root/.config/corax
WORKDIR /corax
COPY . .

ENV VIRTUAL_ENV=/corax/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
ENV PYTHONPATH=/corax

RUN python -m venv $VIRTUAL_ENV && pip3 install --no-cache-dir .

CMD ["bash"]