output "user_names" {
  description = "Names of created IAM users"
  value       = [for u in aws_iam_user.users : u.name]
}

output "user_arns" {
  description = "ARNs of created IAM users"
  value       = [for u in aws_iam_user.users : u.arn]
}

output "console_passwords" {
  description = "Initial console passwords for IAM users (use once; user must change at first login)"
  value = {
    for k, u in aws_iam_user.users :
    k => random_password.user_password[k].result
  }
  sensitive = true
}

output "aws_account_id" {
  description = "AWS Account ID for console login"
  value       = data.aws_caller_identity.current.account_id
}

output "login_instructions" {
  description = "Console login information and credentials for all users"
  value = {
    for k, u in aws_iam_user.users :
    k => {
      username       = u.name
      login_url      = "https://${data.aws_caller_identity.current.account_id}.signin.aws.amazon.com/console"
      account_id     = data.aws_caller_identity.current.account_id
      password_cmd   = "terraform output -json console_passwords | jq -r '.${k}'"
      instructions   = "1. Visit the login_url above\n2. Enter Account ID: ${data.aws_caller_identity.current.account_id}\n3. Enter IAM username: ${u.name}\n4. Get password from: terraform output -json console_passwords | jq -r '.${k}'\n5. You will be forced to change password on first login"
    }
  }
}
