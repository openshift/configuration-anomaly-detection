FROM quay.io/redhat-services-prod/openshift/boilerplate:image-v8.3.4 as builder

ADD . /opt
WORKDIR /opt

RUN make CGO_ENABLED=0 build-cadctl-release
RUN make CGO_ENABLED=0 build-interceptor-release


FROM registry.access.redhat.com/ubi9-minimal:latest as runner

COPY --from=builder /opt/bin/cadctl /bin/cadctl
COPY --from=builder /opt/bin/interceptor /bin/interceptor

ARG BUILD_DATE
ARG VERSION
ARG VCS_REF
ARG DOCKERFILE_PATH

RUN microdnf update -y && \
    microdnf install wget tar gzip -y
RUN wget https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/openshift-client-linux.tar.gz -O /tmp/oc.tar.gz && \
    tar -zxvf /tmp/oc.tar.gz -C /tmp && \
    mv /tmp/oc /bin/oc && \
    rm -f /tmp/oc.tar.gz

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

ENTRYPOINT ["/bin/cadctl"]
