FROM alpine:3.12.2

COPY . /injector
WORKDIR /injector
RUN apk add python3 py3-pip && \
    pip3 install -r requirements.txt && \
    adduser -s /bin/false -S -D -H injector && \
    chown -R injector:root /injector
USER injector
CMD python3 injector.py