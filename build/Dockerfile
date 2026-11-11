FROM quay.io/redhat-services-prod/openshift/boilerplate:latest as builder

ADD . /opt
WORKDIR /opt

RUN make CGO_ENABLED=0 build-cadctl-release
RUN make CGO_ENABLED=0 build-interceptor-release


FROM registry.access.redhat.com/ubi9-minimal:latest@sha256:ecb40c7bdfa5b0bb71e978c98c7cf56ce38edf1f8fb3561078acbc4b13698c07 as runner

COPY --from=builder /opt/bin/cadctl /bin/cadctl
COPY --from=builder /opt/bin/interceptor /bin/interceptor

ARG BUILD_DATE
ARG VERSION
ARG VCS_REF
ARG DOCKERFILE_PATH
ARG OC_VERSION=4.22.21
ARG OC_HASH=daa18c99d81ff3e8e2e2f5f27289d9ed46ca7fa03b04734a63cbdb3f33af022f

RUN microdnf update -y && \
    microdnf install wget tar gzip -y && \
    microdnf clean all
RUN wget https://mirror.openshift.com/pub/openshift-v4/clients/ocp/${OC_VERSION}/openshift-client-linux-${OC_VERSION}.tar.gz -O /tmp/oc.tar.gz && \
    echo "${OC_HASH} /tmp/oc.tar.gz" | sha256sum --check --status && \
    tar -zxvf /tmp/oc.tar.gz -C /tmp && \
    mv /tmp/oc /bin/oc && \
    rm /tmp/kubectl && \
    rm -f /tmp/oc.tar.gz

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
