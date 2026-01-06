output "devops_team_switch_role_arn" {
  description = "ARN of devops-team-switch-tf role"
  value       = aws_iam_role.devops_team_switch.arn
}
