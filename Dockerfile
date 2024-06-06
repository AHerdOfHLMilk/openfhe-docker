FROM ubuntu:20.04
WORKDIR /openfhe-test
COPY . /openfhe-test
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
apt-get -y install \
build-essential \
cmake \
git \
clang-11 && \
# export CXX=/usr/bin/clang++-11 && \
# export CC=/usr/bin/clang && \
apt-get -y install \
libomp5 \
libomp-dev && \
git clone https://github.com/openfheorg/openfhe-development && \
cd openfhe-development && \
mkdir build && cd build && \
cmake .. &&\
cmake .. -DCMAKE_INSTALL_PREFIX=../openfheLib && \
make -j 16 && \
make install && \
make testall && \
bin/examples/pke/simple-integers

