FROM debian:jessie

RUN apt-get update && apt-get install  -y gcc make

COPY . /app

RUN useradd -u 6234 -d /app -M -r fiche \
    && cd /app \
    && make \
    && mkdir /data \
    && chown -R fiche /app /data

USER fiche

WORKDIR /app

EXPOSE 9999

ENTRYPOINT /app/docker-entrypoint.sh
