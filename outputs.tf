output "console_passwords" {
  description = "Initial console passwords for DevOps IAM users"
  value       = module.user.console_passwords
  sensitive   = true
}

output "login_instructions" {
  description = "Console login information and credentials for all users"
  value       = module.user.login_instructions
}

output "get_passwords_command" {
  description = "Command to retrieve sensitive passwords"
  value       = "terraform output -json console_passwords | jq -r '.'"
}
