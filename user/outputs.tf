output "user_names" {
  description = "Names of created IAM users"
  value       = [for u in aws_iam_user.users : u.name]
}

output "user_arns" {
  description = "ARNs of created IAM users"
  value       = [for u in aws_iam_user.users : u.arn]
}
