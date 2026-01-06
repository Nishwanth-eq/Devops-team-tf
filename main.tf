terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

module "policies" {
  source = "./policies"
}

module "role" {
  source = "./role"

  deny_all_if_nomfa_policy_arn   = module.policies.deny_all_if_nomfa_policy_arn
  devops_rbac_level_one_arn      = module.policies.devops_rbac_level_one_arn
  devops_rbac_level_two_arn      = module.policies.devops_rbac_level_two_arn
  devops_rbac_level_three_arn    = module.policies.devops_rbac_level_three_arn
  devops_workload_access_arn     = module.policies.devops_workload_access_arn
}

module "group" {
  source = "./group"

  auth_base_self_service_policy_arn = module.policies.auth_base_self_service_policy_arn
  auth_mfa_enrollment_policy_arn    = module.policies.auth_mfa_enrollment_policy_arn
}

module "user" {
  source = "./user"

  devops_group_name = module.group.devops_group_name
  switch_role_arn   = module.role.devops_team_switch_role_arn
}
