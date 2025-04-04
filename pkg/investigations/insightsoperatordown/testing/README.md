# Testing InsightsOperatorDownSRE

# OCPBUGS-22222

We can induce the symptom of `Failed to pull SCA certs` on a stage cluster by blocking `https://api.stage.openshift.com`
The provided script creates a Rule Group and associates it with your clusters VPC.
Requires awscli and backplane

```
./pkg/investigations/insightsoperatordown/testing/block-api-openshift.sh <cluster-id>
```

# Banned user

TODO

# Additional Resources

- SOP Link https://github.com/openshift/ops-sop/blob/master/v4/troubleshoot/clusteroperators/insights.md
- Alert Definition https://github.com/openshift/managed-cluster-config/blob/master/deploy/sre-prometheus/insights/100-sre-insightsoperator.PrometheusRule.yaml
