output "devops_group_name" {
  description = "Name of devops IAM group"
  value       = aws_iam_group.devops_team.name
}
