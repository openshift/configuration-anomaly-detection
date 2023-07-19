module github.com/openshift/configuration-anomaly-detection

go 1.19

require (
	github.com/PagerDuty/go-pagerduty v1.7.0
	github.com/aws/aws-sdk-go v1.44.302
	github.com/golang/mock v1.6.0
	github.com/onsi/ginkgo/v2 v2.9.1
	github.com/onsi/gomega v1.27.4
	github.com/openshift-online/ocm-sdk-go v0.1.356
	github.com/openshift/aws-account-operator/pkg/apis v0.0.0-20220908090753-666f6cd72cfc
	github.com/openshift/hive/apis v0.0.0-20230714230139-212207882cc9
	github.com/openshift/osd-network-verifier v0.4.0
	github.com/spf13/cobra v1.7.0
	go.uber.org/zap v1.24.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/aws/aws-sdk-go-v2 v1.19.0 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.18.28 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.13.27 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.13.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.35 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.29 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.36 // indirect
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.105.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.29 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.12.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.14.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.19.3 // indirect
	github.com/aws/smithy-go v1.13.5 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/google/pprof v0.0.0-20210720184732-4bb14d4b1be1 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/openshift/custom-resource-status v1.1.3-0.20220503160415-f2fdb4999d87 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/tools v0.7.0 // indirect
)

require (
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/emicklei/go-restful v2.16.0+incompatible // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-openapi/jsonpointer v0.20.0 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/spec v0.20.9 // indirect
	github.com/go-openapi/swag v0.22.4 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang/glog v1.1.1 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/css v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/microcosm-cc/bluemonday v1.0.25 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/openshift/api v0.0.0-20230718161610-2a3e8b481cec // indirect
	github.com/prometheus/client_golang v1.16.0 // indirect
	github.com/prometheus/client_model v0.4.0 // indirect
	github.com/prometheus/common v0.44.0 // indirect
	github.com/prometheus/procfs v0.11.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/net v0.12.0 // indirect
	golang.org/x/sys v0.10.0 // indirect
	golang.org/x/text v0.11.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/api v0.27.3 // indirect
	k8s.io/apimachinery v0.27.3
	k8s.io/klog/v2 v2.100.1 // indirect
	k8s.io/kube-openapi v0.0.0-20230718181711-3c0fae5ee9fd // indirect
	k8s.io/utils v0.0.0-20230711102312-30195339c3c7 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.3.0 // indirect
)

replace (
	k8s.io/api => k8s.io/api v0.0.0-20191016110408-35e52d86657a
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20211108222443-65ecc9d91063
)
