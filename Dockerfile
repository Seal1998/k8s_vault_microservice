FROM alpine:3.12.2

COPY requirements.txt /injector/

RUN adduser -s /bin/false -S -D -H injector && \
    apk add python3 py3-pip && \
    pip3 install --trusted-host pypi.org -r /injector/requirements.txt

COPY --chown=injector:root . /injector/

WORKDIR /injector
USER injector
CMD python3 injector.py
