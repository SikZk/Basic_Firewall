FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        file \
        git \
        iproute2 \
        iputils-ping \
        libssl-dev \
        libboost-all-dev \
        python3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash linuxbrew \
    && /bin/bash -c "curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh | su - linuxbrew -c 'bash'" \
    && su - linuxbrew -c "brew install pcapplusplus"

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sleep", "infinity"]
