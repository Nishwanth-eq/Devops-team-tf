resource "aws_iam_user" "users" {
  for_each = toset(var.usernames)
  name     = each.value
  path     = "/"
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
