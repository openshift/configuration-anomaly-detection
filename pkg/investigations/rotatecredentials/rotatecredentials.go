// Package rotatecredentials implements an investigation that rotates IAM user credentials for non-STS clusters.
package rotatecredentials

import (
	"context"
	"errors"
	"fmt"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awsv1alpha1 "github.com/openshift/aws-account-operator/api/v1alpha1"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	hiveapiv1 "github.com/openshift/hive/apis/hive/v1"
	hiveinternalv1alpha1 "github.com/openshift/hive/apis/hiveinternal/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// OSDManagedAdminIAM is the prefix for the OSD managed admin IAM user
	OSDManagedAdminIAM = "osdManagedAdmin"
	// AWSAccountNamespace is the namespace where AWS Account CRs are stored
	AWSAccountNamespace = "aws-account-operator"
	// CloudCredentialOperatorNamespace is the namespace where CCO runs
	CloudCredentialOperatorNamespace = "openshift-cloud-credential-operator"
)

type Investigation struct{}

// Run verifies that the cluster and AWS account meet the requirements for credential rotation
func (i *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}

	ctx := context.Background()

	// Build resources with cluster, cluster deployment, AWS client, management K8s client, and target cluster K8s client
	r, err := rb.WithCluster().
		WithClusterDeployment().
		WithAwsClient().
		WithManagementK8sClient().
		WithK8sClient().
		WithNotes().
		Build()
	if err != nil {
		return result, err
	}

	// Get the AWS Account CR name from ClusterDeployment namespace
	// The namespace matches the account claim namespace
	accountCRName := r.ClusterDeployment.Namespace

	// Get the AWS Account CR from the management cluster
	account := &awsv1alpha1.Account{}
	err = r.ManagementK8sClient.Get(ctx, types.NamespacedName{
		Namespace: AWSAccountNamespace,
		Name:      accountCRName,
	}, account)
	if err != nil {
		return result, investigation.WrapInfrastructure(
			fmt.Errorf("failed to get AWS Account CR %s from namespace %s: %w", accountCRName, AWSAccountNamespace, err),
			"Failed to retrieve AWS Account information from management cluster")
	}

	// Verify the cluster is not using STS (ManualSTSMode)
	if account.Spec.ManualSTSMode {
		r.Notes.AppendAutomation("Cluster %s uses STS (ManualSTSMode) - No IAM User Credentials to rotate", r.Cluster.ID())
		logging.Infof("Account %s is STS - skipping credential rotation verification", accountCRName)

		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Silence("Cluster uses STS - no IAM credentials to rotate"),
		)
		return result, nil
	}

	r.Notes.AppendSuccess("Cluster is not using STS - credential rotation is applicable")

	// Get the IAM user suffix from the Account CR label
	accountIDSuffixLabel, ok := account.Labels["iamUserId"]
	if !ok {
		r.Notes.AppendWarning("No iamUserId label found on Account CR - cannot determine IAM user")
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Missing iamUserId label on Account CR"),
		)
		return result, nil
	}

	// Get the AWS account ID
	accountID := account.Spec.AwsAccountID
	if accountID == "" {
		r.Notes.AppendWarning("AWS Account ID is empty in Account CR")
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Missing AWS Account ID in Account CR"),
		)
		return result, nil
	}

	r.Notes.AppendAutomation("AWS Account ID: %s", accountID)

	// Determine the osdManagedAdmin username
	// Try with suffix first, then without if needed
	osdManagedAdminUsername := OSDManagedAdminIAM + "-" + accountIDSuffixLabel

	// Verify IAM permissions for rotation
	r.Notes.AppendAutomation("Verifying IAM permissions for user: %s", osdManagedAdminUsername)
	err = verifyRotationPermissions(r.AwsClient, accountID, osdManagedAdminUsername)
	if err != nil {
		// Try without suffix
		logging.Infof("Permission verification failed for %s, trying %s", osdManagedAdminUsername, OSDManagedAdminIAM)
		r.Notes.AppendAutomation("Trying without suffix: %s", OSDManagedAdminIAM)

		err = verifyRotationPermissions(r.AwsClient, accountID, OSDManagedAdminIAM)
		if err != nil {
			r.Notes.AppendWarning("IAM permission verification failed: %s", err.Error())
			result.Actions = append(
				executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
				executor.Escalate("Insufficient IAM permissions for credential rotation"),
			)
			return result, nil
		}
		osdManagedAdminUsername = OSDManagedAdminIAM
	}

	r.Notes.AppendSuccess("IAM permission verification successful for user: %s", osdManagedAdminUsername)

	// Get IAM client for all IAM operations
	baseConfig := r.AwsClient.GetBaseConfig()
	iamClient := iam.NewFromConfig(*baseConfig)

	// Create new IAM access key
	r.Notes.AppendAutomation("Creating new IAM access key for user: %s", osdManagedAdminUsername)

	createAccessKeyOutput, err := iamClient.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{
		UserName: awsSdk.String(osdManagedAdminUsername),
	})
	if err != nil {
		var nse *iamTypes.NoSuchEntityException
		if errors.As(err, &nse) {
			// Try without suffix if user doesn't exist with suffix
			osdManagedAdminUsername = OSDManagedAdminIAM
			r.Notes.AppendAutomation("User not found with suffix, trying: %s", osdManagedAdminUsername)
			createAccessKeyOutput, err = iamClient.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{
				UserName: awsSdk.String(osdManagedAdminUsername),
			})
			if err != nil {
				r.Notes.AppendWarning("Failed to create access key: %s", err.Error())
				result.Actions = append(
					executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
					executor.Escalate("Failed to create new IAM access key"),
				)
				return result, nil
			}
		} else {
			r.Notes.AppendWarning("Failed to create access key: %s", err.Error())
			result.Actions = append(
				executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
				executor.Escalate("Failed to create new IAM access key"),
			)
			return result, nil
		}
	}

	r.Notes.AppendSuccess("Created new access key for user: %s", osdManagedAdminUsername)

	// Prepare new credentials for secrets
	newOsdManagedAdminSecretData := map[string][]byte{
		"aws_user_name":         []byte(*createAccessKeyOutput.AccessKey.UserName),
		"aws_access_key_id":     []byte(*createAccessKeyOutput.AccessKey.AccessKeyId),
		"aws_secret_access_key": []byte(*createAccessKeyOutput.AccessKey.SecretAccessKey),
	}

	// Update secret in aws-account-operator namespace (accountCRName-secret)
	err = updateSecret(ctx, r.ManagementK8sClient, accountCRName+"-secret", AWSAccountNamespace, newOsdManagedAdminSecretData)
	if err != nil {
		r.Notes.AppendWarning("Failed to update secret %s in namespace %s: %s", accountCRName+"-secret", AWSAccountNamespace, err.Error())
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Failed to update Account secret on management cluster"),
		)
		return result, nil
	}
	r.Notes.AppendSuccess("Updated secret: %s/%s", AWSAccountNamespace, accountCRName+"-secret")

	// Update secret in ClusterDeployment namespace (aws)
	err = updateSecret(ctx, r.ManagementK8sClient, "aws", account.Spec.ClaimLinkNamespace, newOsdManagedAdminSecretData)
	if err != nil {
		r.Notes.AppendWarning("Failed to update aws secret in namespace %s: %s", account.Spec.ClaimLinkNamespace, err.Error())
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Failed to update AWS secret in ClusterDeployment namespace"),
		)
		return result, nil
	}
	r.Notes.AppendSuccess("Updated secret: %s/aws", account.Spec.ClaimLinkNamespace)

	// Get ClusterDeployment to use for SyncSet
	cdName := r.ClusterDeployment.Name

	// Create SyncSet to deploy updated credentials to the cluster
	syncSetName := "cad-aws-creds-rotation"
	syncSet := &hiveapiv1.SyncSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      syncSetName,
			Namespace: account.Spec.ClaimLinkNamespace,
		},
		Spec: hiveapiv1.SyncSetSpec{
			ClusterDeploymentRefs: []corev1.LocalObjectReference{
				{
					Name: cdName,
				},
			},
			SyncSetCommonSpec: hiveapiv1.SyncSetCommonSpec{
				ResourceApplyMode: "Upsert",
				Secrets: []hiveapiv1.SecretMapping{
					{
						SourceRef: hiveapiv1.SecretReference{
							Name: "aws",
						},
						TargetRef: hiveapiv1.SecretReference{
							Name:      "aws-creds",
							Namespace: "kube-system",
						},
					},
				},
			},
		},
	}

	r.Notes.AppendAutomation("Creating SyncSet to deploy credentials to cluster")
	err = r.ManagementK8sClient.Create(ctx, syncSet)
	if err != nil {
		r.Notes.AppendWarning("Failed to create SyncSet: %s", err.Error())
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Failed to create SyncSet for credential deployment"),
		)
		return result, nil
	}

	// Wait for SyncSet to complete
	r.Notes.AppendAutomation("Waiting for SyncSet to sync credentials to cluster")
	err = hiveinternalv1alpha1.AddToScheme(r.ManagementK8sClient.Scheme())
	if err != nil {
		logging.Warnf("Failed to add hiveinternalv1alpha1 to scheme: %s", err.Error())
	}

	searchStatus := &hiveinternalv1alpha1.ClusterSync{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cdName,
			Namespace: account.Spec.ClaimLinkNamespace,
		},
	}
	foundStatus := &hiveinternalv1alpha1.ClusterSync{}
	isSSSynced := false

	// Wait up to 30 seconds for sync (6 iterations * 5 seconds)
	for range 6 {
		err = r.ManagementK8sClient.Get(ctx, client.ObjectKeyFromObject(searchStatus), foundStatus)
		if err != nil {
			logging.Warnf("Failed to get ClusterSync status: %s", err.Error())
		} else {
			for _, status := range foundStatus.Status.SyncSets {
				if status.Name == syncSetName {
					if status.FirstSuccessTime != nil {
						isSSSynced = true
						break
					}
				}
			}
		}

		if isSSSynced {
			r.Notes.AppendSuccess("SyncSet successfully synced credentials to cluster")
			break
		}

		time.Sleep(time.Second * 5)
	}

	if !isSSSynced {
		r.Notes.AppendWarning("SyncSet did not complete within timeout - credentials may still be syncing")
	}

	// Clean up the SyncSet
	err = r.ManagementK8sClient.Delete(ctx, syncSet)
	if err != nil {
		logging.Warnf("Failed to delete SyncSet (cleanup): %s", err.Error())
		r.Notes.AppendWarning("Failed to clean up SyncSet %s - manual cleanup may be required", syncSetName)
	} else {
		r.Notes.AppendSuccess("Cleaned up SyncSet: %s", syncSetName)
	}

	// Delete CredentialsRequest objects on target cluster to trigger CCO reconciliation
	// Only proceed if SyncSet was successful
	if isSSSynced {
		r.Notes.AppendAutomation("Deleting CredentialsRequest objects to trigger Cloud Credential Operator reconciliation")
		deletedCount, err := deleteCredentialsRequests(ctx, r.K8sClient)
		switch {
		case err != nil:
			logging.Warnf("Failed to delete CredentialsRequest objects: %s", err.Error())
			r.Notes.AppendWarning("Failed to delete CredentialsRequest objects: %s", err.Error())
			// Don't fail the entire operation if this cleanup step fails
		case deletedCount > 0:
			r.Notes.AppendSuccess("Deleted %d CredentialsRequest object(s) starting with 'openshift'", deletedCount)
		default:
			r.Notes.AppendAutomation("No CredentialsRequest objects found to delete")
		}

		// Delete old IAM access key after successful rotation
		// SAFETY: Only delete if we have exactly 2 keys and the new key has been used at least once
		// AWS only allows 2 active access keys per user, but we must ensure the new key works before deleting the old one
		r.Notes.AppendAutomation("Checking access key status for cleanup")

		// List current access keys NOW (after SyncSet completed and new key should have been used)
		currentKeysOutput, err := iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: awsSdk.String(osdManagedAdminUsername),
		})
		switch {
		case err != nil:
			logging.Warnf("Failed to list current access keys for cleanup: %s", err.Error())
			r.Notes.AppendWarning("Could not list access keys for cleanup - manual cleanup may be required")
		case len(currentKeysOutput.AccessKeyMetadata) == 2:
			// We have 2 keys - find which is the new one we just created
			newKeyID := *createAccessKeyOutput.AccessKey.AccessKeyId
			var oldKeyID string
			var newKeyHasBeenUsed bool

			// Find the old key (the one that's NOT the newly created key)
			for _, key := range currentKeysOutput.AccessKeyMetadata {
				if key.AccessKeyId != nil {
					if *key.AccessKeyId == newKeyID {
						// This is the new key - check if it has been used
						lastUsedOutput, err := iamClient.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
							AccessKeyId: awsSdk.String(newKeyID),
						})
						if err != nil {
							logging.Warnf("Failed to get last used info for new key: %s", err.Error())
						} else if lastUsedOutput.AccessKeyLastUsed != nil && lastUsedOutput.AccessKeyLastUsed.LastUsedDate != nil {
							newKeyHasBeenUsed = true
							r.Notes.AppendSuccess("New access key has been used (last used: %s)", lastUsedOutput.AccessKeyLastUsed.LastUsedDate.String())
						}
					} else {
						// This is the old key
						oldKeyID = *key.AccessKeyId
					}
				}
			}

			switch {
			case oldKeyID != "" && newKeyHasBeenUsed:
				// Disable the old key before deleting
				r.Notes.AppendAutomation("Disabling old access key: %s", oldKeyID)
				_, err = iamClient.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
					UserName:    awsSdk.String(osdManagedAdminUsername),
					AccessKeyId: awsSdk.String(oldKeyID),
					Status:      iamTypes.StatusTypeInactive,
				})
				if err != nil {
					logging.Warnf("Failed to disable old access key %s: %s", oldKeyID, err.Error())
					r.Notes.AppendWarning("Failed to disable old access key %s: %s", oldKeyID, err.Error())
				} else {
					r.Notes.AppendSuccess("Disabled old access key: %s", oldKeyID)
				}

				// Safe to delete the old key
				r.Notes.AppendAutomation("Deleting old access key: %s", oldKeyID)
				_, err = iamClient.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
					UserName:    awsSdk.String(osdManagedAdminUsername),
					AccessKeyId: awsSdk.String(oldKeyID),
				})
				if err != nil {
					logging.Warnf("Failed to delete old access key %s: %s", oldKeyID, err.Error())
					r.Notes.AppendWarning("Failed to delete old access key %s: %s - manual cleanup may be required", oldKeyID, err.Error())
				} else {
					logging.Infof("Deleted old access key: %s", oldKeyID)
					r.Notes.AppendSuccess("Deleted old access key: %s", oldKeyID)
				}
			case oldKeyID != "" && !newKeyHasBeenUsed:
				r.Notes.AppendWarning("New access key has not been used yet - keeping old key %s for safety. Manual cleanup may be required later.", oldKeyID)
			default:
				r.Notes.AppendWarning("Could not identify old key - skipping deletion for safety")
			}
		case len(currentKeysOutput.AccessKeyMetadata) == 1:
			r.Notes.AppendAutomation("Only 1 access key exists (the new one) - no cleanup needed")
		default:
			r.Notes.AppendWarning("Unexpected number of access keys (%d) - skipping old key deletion for safety. Manual cleanup may be required.", len(currentKeysOutput.AccessKeyMetadata))
		}
	}

	r.Notes.AppendSuccess("Successfully rotated credentials for user: %s", osdManagedAdminUsername)

	// Rotate osdCcsAdmin credentials if the account is BYOC (CCS)
	if account.Spec.BYOC {
		r.Notes.AppendAutomation("Account is CCS, rotating osdCcsAdmin credentials")
		createAccessKeyOutputCCS, err := iamClient.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{
			UserName: awsSdk.String("osdCcsAdmin"),
		})
		if err != nil {
			r.Notes.AppendWarning("Failed to create access key for osdCcsAdmin: %s", err.Error())
			result.Actions = append(
				executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
				executor.Escalate("Failed to create new IAM access key for osdCcsAdmin"),
			)
			return result, nil
		}

		newOsdCcsAdminSecretData := map[string][]byte{
			"aws_user_name":         []byte(*createAccessKeyOutputCCS.AccessKey.UserName),
			"aws_access_key_id":     []byte(*createAccessKeyOutputCCS.AccessKey.AccessKeyId),
			"aws_secret_access_key": []byte(*createAccessKeyOutputCCS.AccessKey.SecretAccessKey),
		}

		err = updateSecret(ctx, r.ManagementK8sClient, "byoc", account.Spec.ClaimLinkNamespace, newOsdCcsAdminSecretData)
		if err != nil {
			r.Notes.AppendWarning("Failed to update byoc secret in namespace %s: %s", account.Spec.ClaimLinkNamespace, err.Error())
			result.Actions = append(
				executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
				executor.Escalate("Failed to update byoc secret for osdCcsAdmin"),
			)
			return result, nil
		}

		r.Notes.AppendSuccess("Successfully rotated credentials for user: osdCcsAdmin")
	}

	result.Actions = append(
		executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
		executor.Silence("Credentials successfully rotated"),
	)

	return result, nil
}

// verifyRotationPermissions checks if the AWS client has the necessary IAM permissions
// to perform secret rotation by simulating the required actions on the osdManagedAdmin user
func verifyRotationPermissions(awsClient aws.Client, accountID string, osdManagedAdminUsername string) error {
	// Define the required IAM actions for secret rotation
	requiredActions := []string{
		"iam:CreateAccessKey",
		"iam:CreateUser",
		"iam:DeleteAccessKey",
		"iam:DeleteUser",
		"iam:DeleteUserPolicy",
		"iam:GetUser",
		"iam:GetUserPolicy",
		"iam:ListAccessKeys",
		"iam:PutUserPolicy",
		"iam:TagUser",
	}

	// Construct the ARN for the osdManagedAdmin user
	userArn := fmt.Sprintf("arn:aws:iam::%s:user/%s", accountID, osdManagedAdminUsername)

	logging.Infof("Verifying IAM permissions for user %s", osdManagedAdminUsername)

	// Create IAM client from the AWS client's base config
	baseConfig := awsClient.GetBaseConfig()
	iamClient := iam.NewFromConfig(*baseConfig)

	// Simulate the principal policy to check permissions
	output, err := iamClient.SimulatePrincipalPolicy(context.Background(), &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: awsSdk.String(userArn),
		ActionNames:     requiredActions,
	})
	if err != nil {
		return fmt.Errorf("failed to simulate principal policy: %w", err)
	}

	// Check if all actions are allowed
	var deniedActions []string
	for _, evalResult := range output.EvaluationResults {
		if evalResult.EvalDecision != iamTypes.PolicyEvaluationDecisionTypeAllowed {
			deniedActions = append(deniedActions, *evalResult.EvalActionName)
		}
	}

	if len(deniedActions) > 0 {
		return fmt.Errorf("insufficient permissions for secret rotation. Denied actions: %v", deniedActions)
	}

	logging.Info("Permission verification successful. All required IAM actions are allowed.")
	return nil
}

func (i *Investigation) Name() string {
	return "rotatecredentials"
}

func (i *Investigation) AlertTitle() string {
	return "RotateCredentials"
}

func (i *Investigation) Description() string {
	return "Verifies cluster and AWS account prerequisites for credential rotation"
}

func (i *Investigation) IsExperimental() bool {
	return true
}

// updateSecret updates a Kubernetes secret with new data
func updateSecret(ctx context.Context, k8sClient k8sclient.Client, secretName, namespace string, data map[string][]byte) error {
	secret := &corev1.Secret{}
	err := k8sClient.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      secretName,
	}, secret)
	if err != nil {
		return fmt.Errorf("failed to get secret %s/%s: %w", namespace, secretName, err)
	}

	// Update the secret data
	secret.Data = data

	err = k8sClient.Update(ctx, secret)
	if err != nil {
		return fmt.Errorf("failed to update secret %s/%s: %w", namespace, secretName, err)
	}

	return nil
}

// deleteCredentialsRequests deletes all CredentialsRequest objects in openshift-cloud-credential-operator
// namespace that start with "openshift" to trigger CCO reconciliation with the new credentials
func deleteCredentialsRequests(ctx context.Context, k8sClient k8sclient.Client) (int, error) {
	// Define the CredentialsRequest GVK
	credReqGVK := schema.GroupVersionKind{
		Group:   "cloudcredential.openshift.io",
		Version: "v1",
		Kind:    "CredentialsRequest",
	}

	// List all CredentialsRequest objects in the CCO namespace
	credReqList := &unstructured.UnstructuredList{}
	credReqList.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "cloudcredential.openshift.io",
		Version: "v1",
		Kind:    "CredentialsRequestList",
	})

	err := k8sClient.List(ctx, credReqList, &client.ListOptions{
		Namespace: CloudCredentialOperatorNamespace,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to list CredentialsRequest objects: %w", err)
	}

	deletedCount := 0
	for _, item := range credReqList.Items {
		name := item.GetName()

		// Only delete CredentialsRequest objects that start with "openshift"
		if len(name) >= 9 && name[:9] == "openshift" {
			credReq := &unstructured.Unstructured{}
			credReq.SetGroupVersionKind(credReqGVK)
			credReq.SetName(name)
			credReq.SetNamespace(CloudCredentialOperatorNamespace)

			err = k8sClient.Delete(ctx, credReq)
			if err != nil {
				logging.Warnf("Failed to delete CredentialsRequest %s: %s", name, err.Error())
				// Continue trying to delete other CredentialsRequests
				continue
			}
			logging.Infof("Deleted CredentialsRequest: %s", name)
			deletedCount++
		}
	}

	return deletedCount, nil
}
