FROM ubuntu:22.04

USER root

ENV DEBIAN_FRONTEND=noninteractive

# Install some essentials
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    build-essential \
    libboost-all-dev \
    wget

# Install python3
RUN apt-get install python3-dev python3-pip -y

# Install souffle
RUN wget https://souffle-lang.github.io/ppa/souffle-key.public -O /usr/share/keyrings/souffle-archive-keyring.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/souffle-archive-keyring.gpg] https://souffle-lang.github.io/ppa/ubuntu/ stable main" | tee /etc/apt/sources.list.d/souffle.list
RUN apt-get update && apt-get install souffle -y

# Dependencies for Gigahorse output viz
RUN apt-get update && apt-get install -y graphviz
RUN apt-get update && apt-get install -y libssl-dev

RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install pydot

# Install Rust and Cargo using rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Set the environment path to include Cargo binaries
ENV PATH="/root/.cargo/bin:${PATH}"

# Set up a non-root 'lydia' user
RUN groupadd -r lydia && useradd -ms /bin/bash -g lydia lydia

RUN mkdir -p /opt/lydia

# Copy gigahorse project root
COPY . /opt/lydia/

RUN chown -R lydia:lydia /opt/lydia
RUN chmod -R o+rwx /opt/lydia

# Switch to new 'gigahorse' user context
USER lydia

# Souffle-addon bare-minimum make
RUN cd /opt/lydia/gigahorse-toolchain/souffle-addon && make libsoufflenum.so
# RUN cd /opt/lydia && pip3 install -r requirements.txt

WORKDIR /opt/lydia

# RUN cargo build --release

CMD ["-h"]
ENTRYPOINT ["cargo", "run"]