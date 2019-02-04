FROM debian:stretch
RUN DEBIAN_FRONTEND=noninteractive \
  apt-get update \
  && apt-get install -y -q --no-install-recommends \
          build-essential \
          python \
          git \
          libnl-3-dev \
          pkg-config \
          olsrd \
          iperf3 \
          tcpdump \
  && rm  -rf /var/lib/apt/lists/*
RUN git clone -c http.sslVerify=false --depth 1 --branch ns-3.29 https://github.com/nsnam/ns-3-dev-git.git /root/ns-3.29
WORKDIR /root/ns-3.29
ADD ./docker/bootstrap.tar.gz src/grail/
RUN ./waf configure --enable-tests --enable-examples
RUN ./waf build
ADD ./ src/grail/
RUN ./waf build
CMD bash
