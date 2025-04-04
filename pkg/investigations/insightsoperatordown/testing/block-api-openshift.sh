#!/bin/bash
set -eox pipefail
AWS_PAGER=""
$(ocm backplane cloud credentials -o env $1)
AWS_REGION=$(ocm describe cluster $1 --json | jq -r '.region.id')
FW_RULE_GROUP_ID=$(aws route53resolver create-firewall-rule-group --name "api stage openshift com"  | jq -r '.FirewallRuleGroup.Id')
FW_DOMAIN_LIST_ID=$(aws route53resolver create-firewall-domain-list --name "api stage openshift com" | jq -r '.FirewallDomainList.Id')
aws route53resolver update-firewall-domains --firewall-domain-list-id $FW_DOMAIN_LIST_ID --domains "api.stage.openshift.com" --operation "ADD"
aws route53resolver create-firewall-rule --firewall-rule-group-id $FW_RULE_GROUP_ID --firewall-domain-list-id $FW_DOMAIN_LIST_ID --priority "1" --action "BLOCK" --block-response "NODATA" --name "api stage openshift com"
INFRA_ID=$(ocm describe cluster $1 --json | jq -r '.infra_id')
VPC_ID=$(aws ec2 describe-vpcs --filters "Name=tag-key,Values=kubernetes.io/cluster/$INFRA_ID" | jq -r '.Vpcs[0].VpcId')
aws route53resolver associate-firewall-rule-group --firewall-rule-group-id $FW_RULE_GROUP_ID --name "rgassoc-$VPC_ID-$FW_RULE_GROUP_ID" --priority "1001" --vpc-id $VPC_ID

