variable "deny_all_if_nomfa_policy_arn" {
  type        = string
  description = "ARN of deny-all-if-nomfa-tf policy"
}

variable "devops_rbac_level_one_arn" {
  type        = string
  description = "ARN of devops-rbac-level-one-tf policy"
}

variable "devops_rbac_level_two_arn" {
  type        = string
  description = "ARN of devops-rbac-level-two-tf policy"
}

variable "devops_rbac_level_three_arn" {
  type        = string
  description = "ARN of devops-rbac-level-three-tf policy"
}

variable "devops_workload_access_arn" {
  type        = string
  description = "ARN of devops-workload-access-tf policy"
}
