FROM ubuntu:20.04
RUN apt-get update && \
  apt-get install -y \
  gcc \
  make \
  && rm -rf /var/lib/apt/lists/*
COPY . /app
RUN chmod +x /app/entrypoint.sh
RUN cd /app && make && make install
ENTRYPOINT [ "/app/entrypoint.sh"]