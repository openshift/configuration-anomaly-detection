# Runtime base image. Parameterized so the same Dockerfile can build both the
# current UBI-minimal image (default) and a Red Hat Hardened Image (Hummingbird)
# variant via --build-arg RUNTIME_BASE=... . Declared before the first FROM so
# it is a global build arg usable in the runner FROM below. The default MUST
# remain ubi-minimal so the production build is unchanged.
ARG RUNTIME_BASE=registry.access.redhat.com/ubi9-minimal:latest@sha256:f26ef64172ea61f5ac5ba4be8c5c738bf8760b22b3e5148ce7b40f7308ab32db

ARG OC_VERSION=4.22.21
ARG OC_HASH=daa18c99d81ff3e8e2e2f5f27289d9ed46ca7fa03b04734a63cbdb3f33af022f

# oc has no Hummingbird RPM, so it is fetched from the pinned OpenShift mirror
# tarball and verified against OC_HASH in a Hummingbird builder stage. tar/gzip
# are build-only dependencies of that stage; only the finished oc binary is
# copied into the runner.
FROM registry.access.redhat.com/hi/core-runtime:2.43-openssl-fips-builder as oc-fetcher
ARG OC_VERSION
ARG OC_HASH
USER root
RUN dnf install -y --setopt=install_weak_deps=False tar gzip && \
    dnf clean all
RUN curl -f -o /tmp/oc.tar.gz https://mirror.openshift.com/pub/openshift-v4/clients/ocp/${OC_VERSION}/openshift-client-linux-${OC_VERSION}.tar.gz && \
    echo "${OC_HASH} /tmp/oc.tar.gz" | sha256sum --check --status && \
    tar -zxf /tmp/oc.tar.gz -C /tmp && \
    mv /tmp/oc /bin/oc && \
    rm /tmp/kubectl && \
    rm -f /tmp/oc.tar.gz

FROM quay.io/redhat-services-prod/openshift/boilerplate:latest as builder

ADD . /opt
WORKDIR /opt

RUN make CGO_ENABLED=0 build-cadctl-release
RUN make CGO_ENABLED=0 build-interceptor-release


FROM ${RUNTIME_BASE} as runner

COPY --from=builder /opt/bin/cadctl /bin/cadctl
COPY --from=builder /opt/bin/interceptor /bin/interceptor
COPY --from=oc-fetcher /bin/oc /bin/oc

ARG BUILD_DATE
ARG VERSION
ARG VCS_REF
ARG DOCKERFILE_PATH

LABEL vendor="Red Hat, Inc." \
  name="openshift/configuration-anomaly-detection" \
  description="a CLI tool to detect and mitigate configuration mishaps" \
  io.k8s.display-name="openshift/configuration-anomaly-detection" \
  io.k8s.description="a CLI tool to detect and mitigate configuration mishaps" \
  maintainer="Red Hat, Inc." \
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

ENTRYPOINT ["/bin/cadctl"]
