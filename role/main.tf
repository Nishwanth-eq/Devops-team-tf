resource "aws_iam_role" "devops_team_switch" {
  name = "devops-team-switch-tf"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::434793037400:root"
        }
        Action    = "sts:AssumeRole"
        Condition = {}
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_deny_all_if_nomfa" {
  role       = aws_iam_role.devops_team_switch.name
  policy_arn = var.deny_all_if_nomfa_policy_arn
}

resource "aws_iam_role_policy_attachment" "attach_devops_rbac_level_one" {
  role       = aws_iam_role.devops_team_switch.name
  policy_arn = var.devops_rbac_level_one_arn
}

resource "aws_iam_role_policy_attachment" "attach_devops_rbac_level_two" {
  role       = aws_iam_role.devops_team_switch.name
  policy_arn = var.devops_rbac_level_two_arn
}

resource "aws_iam_role_policy_attachment" "attach_devops_rbac_level_three" {
  role       = aws_iam_role.devops_team_switch.name
  policy_arn = var.devops_rbac_level_three_arn
}

resource "aws_iam_role_policy_attachment" "attach_devops_workload_access" {
  role       = aws_iam_role.devops_team_switch.name
  policy_arn = var.devops_workload_access_arn
}
