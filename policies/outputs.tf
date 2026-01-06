output "auth_base_self_service_policy_arn" {
  description = "ARN of auth-base-self-service-tf policy"
  value       = aws_iam_policy.auth_base_self_service.arn
}

output "auth_mfa_enrollment_policy_arn" {
  description = "ARN of auth-mfa-enrollment-tf policy"
  value       = aws_iam_policy.auth_mfa_enrollment.arn
}

output "deny_all_if_nomfa_policy_arn" {
  description = "ARN of deny-all-if-nomfa-tf policy"
  value       = aws_iam_policy.deny_all_if_nomfa.arn
}

output "devops_rbac_level_one_arn" {
  description = "ARN of devops-rbac-level-one-tf policy"
  value       = aws_iam_policy.devops_rbac_level_one.arn
}

output "devops_rbac_level_two_arn" {
  description = "ARN of devops-rbac-level-two-tf policy"
  value       = aws_iam_policy.devops_rbac_level_two.arn
}

output "devops_rbac_level_three_arn" {
  description = "ARN of devops-rbac-level-three-tf policy"
  value       = aws_iam_policy.devops_rbac_level_three.arn
}

output "devops_workload_access_arn" {
  description = "ARN of devops-workload-access-tf policy"
  value       = aws_iam_policy.devops_workload_access.arn
}
