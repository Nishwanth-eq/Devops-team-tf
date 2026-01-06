output "console_passwords" {
  description = "Initial console passwords for DevOps IAM users"
  value       = module.user.console_passwords
  sensitive   = true
}
