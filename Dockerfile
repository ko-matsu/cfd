FROM --platform=$TARGETPLATFORM debian:bullseye-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends git cmake build-essential \
  && apt-get -y clean \
  && rm -rf /var/lib/apt/lists/*

RUN git config --global http.sslverify false

WORKDIR /workspace
COPY . .

# build & 
RUN ./tools/simple_build.sh \
  && ./tools/simple_test.sh
