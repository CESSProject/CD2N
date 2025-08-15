FROM --platform=linux/amd64 gramine-rust:latest AS builder

WORKDIR /root
ENV HOME=/root
ARG APP_NAME="justicar"
RUN mkdir -p $HOME/${APP_NAME}
ARG SGX_SIGNER_KEY="enclave-key.pem"
ARG APP_BASE_DIR="/opt/justicar"

COPY crates $HOME/${APP_NAME}/crates
COPY justicar $HOME/${APP_NAME}/justicar
COPY scripts $HOME/${APP_NAME}/scripts
COPY Cargo.toml Cargo.lock rust-toolchain.toml $HOME/${APP_NAME}/

RUN cd $HOME/${APP_NAME}/justicar/gramine-build && \
    PATH="$PATH:$HOME/.cargo/bin" make dist PREFIX="${APP_BASE_DIR}" && \
    PATH="$PATH:$HOME/.cargo/bin" make clean

# ====

FROM --platform=linux/amd64 gramine:latest AS runtime

ARG ENV_NAME
ENV ENV_NAME=$ENV_NAME
RUN echo "Gramine SGX Version:" && gramine-sgx --version
ARG APP_BASE_DIR="/opt/justicar"
ARG APP_RELEASE_DIR="${APP_BASE_DIR}/release/${ENV_NAME}"

RUN mkdir -p ${APP_RELEASE_DIR}
COPY --from=builder ${APP_BASE_DIR} ${APP_RELEASE_DIR}
ADD scripts/start_justicar.sh ${APP_RELEASE_DIR}/start_justicar.sh
ADD scripts/start_handover.sh ${APP_BASE_DIR}/start_handover.sh
ADD dockerfile/conf /opt/conf

RUN mv ${APP_RELEASE_DIR}/handover-script ${APP_BASE_DIR}
RUN chmod 777 "${APP_RELEASE_DIR}/start_justicar.sh"
RUN chmod 777 "${APP_BASE_DIR}/start_handover.sh"

WORKDIR ${APP_BASE_DIR}

ENV SGX=1
ENV SKIP_AESMD=0
ENV SLEEP_BEFORE_START=6
ENV RUST_LOG="debug"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/bin/bash", "start_handover.sh"]