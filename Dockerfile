FROM golang:1.17.7-alpine3.15 as builder

RUN apk add --update --no-cache ca-certificates tzdata git make bash && update-ca-certificates

ADD . /opt
WORKDIR /opt

# CGO_ENABLED is set to allow the golang binary build to work on the ubi image
RUN git update-index --refresh; make CGO_ENABLED=0 cadctl-install-local-force

FROM quay.io/app-sre/ubi8-ubi-minimal:8.5-204 as runner

COPY --from=builder /opt/cadctl/cadctl /bin/cadctl

ARG BUILD_DATE
ARG VERSION
ARG VCS_REF
ARG DOCKERFILE_PATH

LABEL vendor="RedHat" \
    name="openshift/configuration-anomaly-detection" \
    description="a CLI tool to detect and mitigate configuration mishaps" \
    io.k8s.display-name="openshift/configuration-anomaly-detection" \
    io.k8s.description="a CLI tool to detect and mitigate configuration mishaps" \
    maintainer="RedHat <>" \
    version="$VERSION" \
    org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.description="a CLI tool to detect and mitigate configuration mishaps" \
    org.label-schema.docker.cmd="docker run --rm openshift/configuration-anomaly-detection" \
    org.label-schema.docker.dockerfile=$DOCKERFILE_PATH \
    org.label-schema.name="openshift/configuration-anomaly-detection" \
    org.label-schema.schema-version="0.1.0" \
    org.label-schema.vcs-branch=$VCS_BRANCH \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url="https://github.com/openshift/configuration-anomaly-detection" \
    org.label-schema.vendor="openshift/configuration-anomaly-detection" \
    org.label-schema.version=$VERSION

RUN microdnf install jq

ENTRYPOINT ["/bin/cadctl"]
