FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    python3-pip ninja-build build-essential flex bison git cmake \
    libsctp-dev libgnutls28-dev libgcrypt20-dev libssl-dev libidn11-dev libmongoc-dev libbson-dev \
    libyaml-dev libnghttp2-dev libmicrohttpd-dev libcurl4-gnutls-dev net-tools iproute2 meson \
    libtalloc-dev libadns1-dev
RUN git clone https://github.com/open5gs/open5gs && cd open5gs && \
    meson build --prefix=/install && ninja -C build install
WORKDIR /install/bin
