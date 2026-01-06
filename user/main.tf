resource "aws_iam_user" "users" {
  for_each = toset(var.usernames)
  name     = each.value
  path     = "/"
  force_destroy  = true

  provisioner "local-exec" {
    when    = destroy
    command = "aws iam delete-login-profile --user-name ${self.name} --region us-east-1 || true"
  }
}

# Add each created user into the provided devops group
resource "aws_iam_user_group_membership" "membership" {
  for_each = aws_iam_user.users
  user     = each.value.name
  groups   = [var.devops_group_name]
}

# Inline policy per-user to allow switching to a specific role
resource "aws_iam_user_policy" "switch_role" {
  for_each = aws_iam_user.users
  name     = "${each.value.name}-inline"
  user     = each.value.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid     = "AllowSwitchToOwnRole"
        Effect  = "Allow"
        Action  = "sts:AssumeRole"
        Resource = var.switch_role_arn
      }
    ]
  })
}

resource "random_password" "user_password" {
  for_each = aws_iam_user.users

  length      = 16
  special     = true
  min_upper   = 2
  min_lower   = 2
  min_numeric = 2
  min_special = 2
}

#resource "aws_iam_user_login_profile" "this" {
#  for_each = aws_iam_user.users
#
#  user                    = each.value.name
#  password                = random_password.user_password[each.key].result
#  password_reset_required = true
#}

resource "null_resource" "create_login_profile" {
  for_each = aws_iam_user.users

  provisioner "local-exec" {
    command = "aws iam create-login-profile --user-name ${each.value.name} --password ${jsonencode(random_password.user_password[each.key].result)} --password-reset-required --region us-east-1"
  }

  depends_on = [aws_iam_user.users]
}

data "aws_caller_identity" "current" {}
