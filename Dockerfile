FROM alpine:3.7 as builder

RUN apk add --no-cache \
    curl \
    gcc \
    make \
    musl-dev


COPY * /usr/src/fiche/

WORKDIR /usr/src/fiche

RUN make -f Makefile

FROM alpine:3.7 as runner

EXPOSE 9999

COPY --from=builder /usr/src/fiche/fiche /fiche/

WORKDIR /fiche/
ENV PATH /fiche:$PATH

ENTRYPOINT ["fiche"]
CMD ["-h"]
