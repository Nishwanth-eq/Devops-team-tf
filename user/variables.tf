variable "devops_group_name" {
  type        = string
  description = "IAM group name to attach user to"
}

variable "switch_role_arn" {
  type        = string
  description = "ARN of devops-team-switch-tf role that user can assume"
}
variable "usernames" {
  type        = list(string)
  description = "List of IAM usernames to create"
}
