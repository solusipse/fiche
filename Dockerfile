FROM alpine

COPY fiche /usr/bin/fiche
RUN mkdir fiche && \
		adduser fiche -D && \
		chmod 755 /usr/bin/fiche && \
		chown fiche:fiche /usr/bin/fiche
VOLUME /fiche		
USER fiche
CMD /usr/bin/fiche
