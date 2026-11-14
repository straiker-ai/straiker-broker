# syntax=docker/dockerfile:1
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/straiker-broker ./cmd/straiker-broker \
 && sh scripts/third-party-notices.sh /out/THIRD_PARTY_NOTICES ./cmd/straiker-broker \
 && mkdir -p /out/state

# No shell, no package manager: the broker and the CA store, as a non-root user.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/straiker-broker /usr/local/bin/straiker-broker
COPY --from=build /src/LICENSE /out/THIRD_PARTY_NOTICES /usr/share/doc/straiker-broker/
COPY --from=build --chown=65532:65532 /out/state /var/lib/straiker-broker
ENV BROKER_STATE_DIR=/var/lib/straiker-broker
VOLUME ["/var/lib/straiker-broker"]
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/straiker-broker"]
