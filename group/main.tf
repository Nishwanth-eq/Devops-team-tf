resource "aws_iam_group" "devops_team" {
  name = "devops-teams-tf"
}

resource "aws_iam_group_policy_attachment" "attach_auth_base_self_service" {
  group      = aws_iam_group.devops_team.name
  policy_arn = var.auth_base_self_service_policy_arn
}

resource "aws_iam_group_policy_attachment" "attach_auth_mfa_enrollment" {
  group      = aws_iam_group.devops_team.name
  policy_arn = var.auth_mfa_enrollment_policy_arn
}
