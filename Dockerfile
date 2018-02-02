FROM alpine



ENV INSIDE_TCP_PORT 1024
ENV OUTPUT_DIR /app/outputs
ENV VIRTUAL_HOST fiche.localhost

RUN addgroup -S fiche && adduser -S -G fiche fiche && mkdir -p /app/outputs && chown -R fiche:fiche /app/outputs

ADD * /src/

WORKDIR /src

RUN apk update && apk add alpine-sdk && make && make install && rm -rf /src/* && rm -rf /var/cache/apk/*

USER fiche

WORKDIR /app

ENTRYPOINT /usr/local/bin/fiche -o $OUTPUT_DIR -p $INSIDE_TCP_PORT -d $VIRTUAL_HOST

EXPOSE $INSIDE_TCP_PORT

VOLUME $OUTPUT_DIR
