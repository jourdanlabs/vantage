# SYNTHETIC — function-call syntax. Not copied from any hold-out.
# Exercises merge / cidrsubnet / format / jsonencode / file / concat.

locals {
  common = {
    env = var.env
  }
  extra_actions = ["s3:GetObject"]
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "env" {
  type    = string
  default = "synth"
}

resource "aws_vpc" "synth" {
  cidr_block = var.vpc_cidr
  tags       = merge(local.common, { Name = format("%s-vpc", var.env) })
}

resource "aws_subnet" "synth" {
  vpc_id            = aws_vpc.synth.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 1)
  availability_zone = format("%s%s", var.region, "a")
  tags              = merge(local.common, { Name = format("%s-subnet", var.env) })
}

resource "aws_iam_role" "synth" {
  name = format("vantage-synth-role-%s", var.env)
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, { Name = format("role-%s", var.env) })
}

resource "aws_iam_policy" "synth" {
  name   = format("%s-policy", var.env)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = "*"
      }],
      [{
        Effect   = "Allow"
        Action   = local.extra_actions
        Resource = format("arn:aws:s3:::%s/*", var.env)
      }]
    )
  })
}

resource "aws_s3_bucket" "synth_policy_src" {
  bucket = format("%s-fixture-bucket", var.env)
  acl    = "private"
}

data "local_file" "synth" {
  filename = file("${path.module}/does-not-need-to-exist.txt")
}
