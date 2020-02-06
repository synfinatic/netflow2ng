FROM ruby

RUN apt-get update && \
    apt-get install -y git make rpm golang libzmq5 libzmq3-dev && \
    gem install fpm

WORKDIR /work

ENTRYPOINT [ "/bin/bash" ]
