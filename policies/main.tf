#############################
# 1) auth-base-self-service-tf
#############################
resource "aws_iam_policy" "auth_base_self_service" {
  name   = "auth-base-self-service-tf"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ViewAccountAndIdentityBasics"
        Effect = "Allow"
        Action = [
          "iam:GetUser",
          "iam:GetLoginProfile",
          "iam:GetAccountPasswordPolicy",
          "iam:GetAccountSummary",
          "iam:ListAccountAliases",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ListAccessKeys"
        ]
        Resource = "*"
      },
      {
        Sid    = "ManageOwnPasswordAndLoginProfile"
        Effect = "Allow"
        Action = [
          "iam:ChangePassword",
          "iam:UpdateLoginProfile"
        ]
  Resource = "arn:aws:iam::*:user/$${aws:username}"
      }
    ]
  })
}

#############################
# 2) auth-mfa-enrollment-tf
#############################
resource "aws_iam_policy" "auth_mfa_enrollment" {
  name   = "auth-mfa-enrollment-tf"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CreateAndManageOwnVirtualMFA"
        Effect = "Allow"
        Action = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ResyncMFADevice",
          "iam:DeactivateMFADevice",
          "iam:DeleteVirtualMFADevice"
        ]
        Resource = "*"
      },
      {
        Sid    = "ListMFAForSelf"
        Effect = "Allow"
        Action = [
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices"
        ]
        Resource = "*"
      }
    ]
  })
}

#############################
# 3) deny-all-if-nomfa-tf
#############################
resource "aws_iam_policy" "deny_all_if_nomfa" {
  name   = "deny-all-if-nomfa-tf"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyAllActionsWithoutMFA"
        Effect   = "Deny"
        NotAction = [
          "iam:GetUser",
          "iam:GetLoginProfile",
          "iam:GetAccountSummary",
          "iam:ListAccessKeys",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ResyncMFADevice",
          "iam:DeactivateMFADevice",
          "iam:DeleteVirtualMFADevice",
          "iam:ChangePassword",
          "iam:UpdateLoginProfile",
          "iam:GetAccountPasswordPolicy",
          "iam:ListAccountAliases",
          "sts:GetSessionToken"
        ]
        Resource  = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}

#############################
# 4) devops-rbac-level-one-tf
#############################
resource "aws_iam_policy" "devops_rbac_level_one" {
  name   = "devops-rbac-level-one-tf"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TaggingForDevOpsServices"
        Effect = "Allow"
        Action = [
          "iam:TagUser",
          "iam:UntagUser",
          "iam:ListUserTags",
          "iam:TagGroup",
          "iam:UntagGroup",
          "iam:ListGroupTags",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "secretsmanager:TagResource",
          "secretsmanager:UntagResource",
          "acm:AddTagsToCertificate",
          "acm:RemoveTagsFromCertificate",
          "amplify:TagResource",
          "amplify:UntagResource",
          "logs:TagLogGroup",
          "logs:UntagLogGroup"
        ]
        Resource = "*"
      },
      {
        Sid    = "SSMSessionManagerForHumans"
        Effect = "Allow"
        Action = [
          "ssm:StartSession",
          "ssm:TerminateSession",
          "ssm:ResumeSession",
          "ssm:DescribeSessions",
          "ssm:GetConnectionStatus",
          "ssm:DescribeInstanceInformation",
          "ssm:DescribeDocument",
          "ssm:GetDocument"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchMetricsAndAlarmsRW"
        Effect = "Allow"
        Action = [
          "cloudwatch:DescribeAlarms",
          "cloudwatch:DescribeAlarmHistory",
          "cloudwatch:GetMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics",
          "cloudwatch:PutMetricAlarm",
          "cloudwatch:DeleteAlarms",
          "cloudwatch:SetAlarmState"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchLogsRW"
        Effect = "Allow"
        Action = [
          "logs:Describe*",
          "logs:Get*",
          "logs:FilterLogEvents",
          "logs:StartQuery",
          "logs:StopQuery",
          "logs:GetQueryResults",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutRetentionPolicy",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      },
      {
        Sid    = "SecretsManagerReadWrite"
        Effect = "Allow"
        Action = [
          "secretsmanager:ListSecrets",
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:CreateSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecret",
          "secretsmanager:RotateSecret"
        ]
        Resource = "*"
      },
      {
        Sid    = "KMSDecryptForSecretsManagerOnly"
        Effect = "Allow"
        Action = "kms:Decrypt"
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = [
              "secretsmanager.ap-south-1.amazonaws.com",
              "secretsmanager.us-east-1.amazonaws.com"
            ]
          }
        }
      },
      {
        Sid    = "ACMReadWrite"
        Effect = "Allow"
        Action = [
          "acm:ListCertificates",
          "acm:DescribeCertificate",
          "acm:GetCertificate",
          "acm:RequestCertificate",
          "acm:ImportCertificate",
          "acm:DeleteCertificate",
          "acm:AddTagsToCertificate",
          "acm:RemoveTagsFromCertificate"
        ]
        Resource = "*"
      },
      {
        Sid    = "AmplifyReadWrite"
        Effect = "Allow"
        Action = [
          "amplify:ListApps",
          "amplify:GetApp",
          "amplify:CreateApp",
          "amplify:DeleteApp",
          "amplify:UpdateApp",
          "amplify:ListBranches",
          "amplify:GetBranch",
          "amplify:CreateBranch",
          "amplify:DeleteBranch",
          "amplify:UpdateBranch",
          "amplify:ListJobs",
          "amplify:GetJob",
          "amplify:StartJob",
          "amplify:StopJob"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudTrailReadOnly"
        Effect = "Allow"
        Action = [
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:GetEventSelectors",
          "cloudtrail:ListTrails",
          "cloudtrail:LookupEvents"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMIdentityCenterAdmin"
        Effect = "Allow"
        Action = [
          "sso:*",
          "identitystore:*",
          "sso-directory:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "OrganizationsForIdentityCenter"
        Effect = "Allow"
        Action = [
          "organizations:DescribeOrganization",
          "organizations:ListAccounts",
          "organizations:ListRoots",
          "organizations:ListOrganizationalUnitsForParent",
          "organizations:ListParents",
          "organizations:ListDelegatedAdministrators",
          "organizations:RegisterDelegatedAdministrator",
          "organizations:DeregisterDelegatedAdministrator",
          "organizations:EnableAWSServiceAccess",
          "organizations:DisableAWSServiceAccess",
          "organizations:ListAWSServiceAccessForOrganization"
        ]
        Resource = "*"
      },
      {
        Sid    = "CreateServiceLinkedRoles"
        Effect = "Allow"
        Action = "iam:CreateServiceLinkedRole"
        Resource = "*"
        Condition = {
          StringEquals = {
            "iam:AWSServiceName" = [
              "sso.amazonaws.com",
              "ssm.amazonaws.com",
              "ecs.amazonaws.com",
              "elasticloadbalancing.amazonaws.com",
              "autoscaling.amazonaws.com"
            ]
          }
        }
      }
    ]
  })
}

#############################
# 5) devops-rbac-level-two-tf
#############################
resource "aws_iam_policy" "devops_rbac_level_two" {
  name   = "devops-rbac-level-two-tf"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Full"
        Effect = "Allow"
        Action = "ec2:*"
        Resource = "*"
      },
      {
        Sid    = "S3Full"
        Effect = "Allow"
        Action = [
          "s3:*",
          "s3-object-lambda:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMReadOnly"
        Effect = "Allow"
        Action = [
          "iam:Get*",
          "iam:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ManageDevOpsRolesProfiles"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:UpdateRole",
          "iam:UpdateAssumeRolePolicy",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:PutRolePermissionsBoundary",
          "iam:DeleteRolePermissionsBoundary",
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile"
        ]
        Resource = [
          "arn:aws:iam::434793037400:role/devops-*",
          "arn:aws:iam::434793037400:instance-profile/devops-*"
        ]
      },
      {
        Sid    = "RequireBoundaryOnCreateRole"
        Effect = "Allow"
        Action = "iam:CreateRole"
        Resource = "arn:aws:iam::434793037400:role/devops-*"
        Condition = {
          StringEquals = {
            "iam:PermissionsBoundary" = "arn:aws:iam::434793037400:policy/DevOpsBoundary"
          }
        }
      },
      {
        Sid    = "ManageDevOpsPolicies"
        Effect = "Allow"
        Action = [
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:CreatePolicyVersion",
          "iam:DeletePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:TagPolicy",
          "iam:UntagPolicy"
        ]
        Resource = "arn:aws:iam::434793037400:policy/devops-*"
      },
      {
        Sid    = "PassDevOpsRolesToEC2Only"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = "arn:aws:iam::434793037400:role/devops-*"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ec2.amazonaws.com"
          }
        }
      }
    ]
  })
}

#############################
# 6) devops-rbac-level-three-tf
#############################
resource "aws_iam_policy" "devops_rbac_level_three" {
  name   = "devops-rbac-level-three-tf"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EquicomInlineIAM"
        Effect = "Allow"
        Action = [
          "iam:CreateUser",
          "iam:DeleteUser",
          "iam:UpdateUser",
          "iam:GetUser",
          "iam:ListUsers",
          "iam:CreateGroup",
          "iam:DeleteGroup",
          "iam:UpdateGroup",
          "iam:GetGroup",
          "iam:ListGroups",
          "iam:AddUserToGroup",
          "iam:RemoveUserFromGroup",
          "iam:AttachUserPolicy",
          "iam:DetachUserPolicy",
          "iam:AttachGroupPolicy",
          "iam:DetachGroupPolicy",
          "iam:ListAttachedUserPolicies",
          "iam:ListAttachedGroupPolicies",
          "iam:PutUserPolicy",
          "iam:DeleteUserPolicy",
          "iam:GetUserPolicy",
          "iam:ListUserPolicies",
          "iam:PutGroupPolicy",
          "iam:DeleteGroupPolicy",
          "iam:GetGroupPolicy",
          "iam:ListGroupPolicies",
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:CreatePolicyVersion",
          "iam:DeletePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicies",
          "iam:ListPolicyVersions",
          "iam:CreateLoginProfile",
          "iam:UpdateLoginProfile",
          "iam:DeleteLoginProfile",
          "iam:CreateAccessKey",
          "iam:UpdateAccessKey",
          "iam:DeleteAccessKey",
          "iam:ListAccessKeys",
          "iam:ListMFADevices",
          "iam:EnableMFADevice",
          "iam:DeactivateMFADevice",
          "iam:ResyncMFADevice",
          "iam:PassRole"
        ]
        Resource = "*"
      },
      {
        Sid    = "EquicomInlineEC2"
        Effect = "Allow"
        Action = [
          "autoscaling:CreateAutoScalingGroup",
          "autoscaling:UpdateAutoScalingGroup",
          "autoscaling:DeleteAutoScalingGroup",
          "autoscaling:SetDesiredCapacity",
          "autoscaling:TerminateInstanceInAutoScalingGroup",
          "autoscaling:SuspendProcesses",
          "autoscaling:ResumeProcesses",
          "autoscaling:PutScalingPolicy",
          "autoscaling:DeletePolicy",
          "autoscaling:PutScheduledUpdateGroupAction",
          "autoscaling:DeleteScheduledAction",
          "autoscaling:AttachLoadBalancerTargetGroups",
          "autoscaling:DetachLoadBalancerTargetGroups",
          "autoscaling:Describe*",
          "ec2:CreateLaunchTemplate",
          "ec2:CreateLaunchTemplateVersion",
          "ec2:ModifyLaunchTemplate",
          "ec2:DeleteLaunchTemplate",
          "ec2:DeleteLaunchTemplateVersions",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:CreateImage",
          "ec2:CopyImage",
          "ec2:DeregisterImage",
          "ec2:ModifyImageAttribute",
          "ec2:DescribeImages",
          "ec2:CreateSnapshot",
          "ec2:DeleteSnapshot",
          "ec2:ModifySnapshotAttribute",
          "ec2:DescribeSnapshots",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeKeyPairs",
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "EquicomInlineS3"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "*"
      },
      {
        Sid    = "EquicomInlineDynamoDB"
        Effect = "Allow"
        Action = [
          "dynamodb:DescribeTable",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
          "dynamodb:UpdateItem"
        ]
        Resource = "*"
      }
    ]
  })
}

#############################
# 7) devops-workload-access-tf
#############################
resource "aws_iam_policy" "devops_workload_access" {
  name   = "devops-workload-access-tf"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SSMSessionAccess"
        Effect = "Allow"
        Action = [
          "ssm:StartSession",
          "ssm:ResumeSession",
          "ssm:TerminateSession",
          "ssm:DescribeSessions",
          "ssm:GetConnectionStatus"
        ]
        Resource = "*"
      },
      {
        Sid    = "SSMTargetDiscovery"
        Effect = "Allow"
        Action = [
          "ssm:DescribeInstanceInformation",
          "ssm:DescribeDocument",
          "ssm:GetDocument",
          "ssm:ListDocuments"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2ReadOnlyForSSM"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeImages",
          "ec2:DescribeTags",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchReadOnly"
        Effect = "Allow"
        Action = [
          "cloudwatch:Describe*",
          "cloudwatch:Get*",
          "cloudwatch:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchLogsReadOnly"
        Effect = "Allow"
        Action = [
          "logs:Describe*",
          "logs:Get*",
          "logs:FilterLogEvents",
          "logs:StartQuery",
          "logs:StopQuery",
          "logs:GetQueryResults"
        ]
        Resource = "*"
      }
    ]
  })
}
