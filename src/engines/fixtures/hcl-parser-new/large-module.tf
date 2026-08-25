# SYNTHETIC large module — generated 2026-08-18. Not copied from any hold-out.
# Repeated resource blocks to exercise bounded parse time/memory.
# Target size 50–200KB of unique-per-index blocks.

locals {
  common = { owner = "vantage-synth", suite = "hcl-parser-new" }
}

resource "aws_iam_role" "synth_0" {
  name = format("vantage-synth-role-%s", "0")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "0")
    idx  = 0
  })
}

resource "aws_subnet" "synth_0" {
  vpc_id     = format("vpc-synth-%s", "0")
  cidr_block = cidrsubnet("10.0.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "0") })
}

resource "aws_iam_role" "synth_1" {
  name = format("vantage-synth-role-%s", "1")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "1")
    idx  = 1
  })
}

resource "aws_subnet" "synth_1" {
  vpc_id     = format("vpc-synth-%s", "1")
  cidr_block = cidrsubnet("10.1.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "1") })
}

resource "aws_iam_role" "synth_2" {
  name = format("vantage-synth-role-%s", "2")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "2")
    idx  = 2
  })
}

resource "aws_subnet" "synth_2" {
  vpc_id     = format("vpc-synth-%s", "2")
  cidr_block = cidrsubnet("10.2.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "2") })
}

resource "aws_iam_role" "synth_3" {
  name = format("vantage-synth-role-%s", "3")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "3")
    idx  = 3
  })
}

resource "aws_subnet" "synth_3" {
  vpc_id     = format("vpc-synth-%s", "3")
  cidr_block = cidrsubnet("10.3.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "3") })
}

resource "aws_iam_role" "synth_4" {
  name = format("vantage-synth-role-%s", "4")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "4")
    idx  = 4
  })
}

resource "aws_subnet" "synth_4" {
  vpc_id     = format("vpc-synth-%s", "4")
  cidr_block = cidrsubnet("10.4.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "4") })
}

resource "aws_iam_role" "synth_5" {
  name = format("vantage-synth-role-%s", "5")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "5")
    idx  = 5
  })
}

resource "aws_subnet" "synth_5" {
  vpc_id     = format("vpc-synth-%s", "5")
  cidr_block = cidrsubnet("10.5.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "5") })
}

resource "aws_iam_role" "synth_6" {
  name = format("vantage-synth-role-%s", "6")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "6")
    idx  = 6
  })
}

resource "aws_subnet" "synth_6" {
  vpc_id     = format("vpc-synth-%s", "6")
  cidr_block = cidrsubnet("10.6.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "6") })
}

resource "aws_iam_role" "synth_7" {
  name = format("vantage-synth-role-%s", "7")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "7")
    idx  = 7
  })
}

resource "aws_subnet" "synth_7" {
  vpc_id     = format("vpc-synth-%s", "7")
  cidr_block = cidrsubnet("10.7.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "7") })
}

resource "aws_iam_role" "synth_8" {
  name = format("vantage-synth-role-%s", "8")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "8")
    idx  = 8
  })
}

resource "aws_subnet" "synth_8" {
  vpc_id     = format("vpc-synth-%s", "8")
  cidr_block = cidrsubnet("10.8.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "8") })
}

resource "aws_iam_role" "synth_9" {
  name = format("vantage-synth-role-%s", "9")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "9")
    idx  = 9
  })
}

resource "aws_subnet" "synth_9" {
  vpc_id     = format("vpc-synth-%s", "9")
  cidr_block = cidrsubnet("10.9.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "9") })
}

resource "aws_iam_role" "synth_10" {
  name = format("vantage-synth-role-%s", "10")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "10")
    idx  = 10
  })
}

resource "aws_subnet" "synth_10" {
  vpc_id     = format("vpc-synth-%s", "10")
  cidr_block = cidrsubnet("10.10.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "10") })
}

resource "aws_iam_role" "synth_11" {
  name = format("vantage-synth-role-%s", "11")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "11")
    idx  = 11
  })
}

resource "aws_subnet" "synth_11" {
  vpc_id     = format("vpc-synth-%s", "11")
  cidr_block = cidrsubnet("10.11.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "11") })
}

resource "aws_iam_role" "synth_12" {
  name = format("vantage-synth-role-%s", "12")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "12")
    idx  = 12
  })
}

resource "aws_subnet" "synth_12" {
  vpc_id     = format("vpc-synth-%s", "12")
  cidr_block = cidrsubnet("10.12.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "12") })
}

resource "aws_iam_role" "synth_13" {
  name = format("vantage-synth-role-%s", "13")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "13")
    idx  = 13
  })
}

resource "aws_subnet" "synth_13" {
  vpc_id     = format("vpc-synth-%s", "13")
  cidr_block = cidrsubnet("10.13.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "13") })
}

resource "aws_iam_role" "synth_14" {
  name = format("vantage-synth-role-%s", "14")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "14")
    idx  = 14
  })
}

resource "aws_subnet" "synth_14" {
  vpc_id     = format("vpc-synth-%s", "14")
  cidr_block = cidrsubnet("10.14.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "14") })
}

resource "aws_iam_role" "synth_15" {
  name = format("vantage-synth-role-%s", "15")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "15")
    idx  = 15
  })
}

resource "aws_subnet" "synth_15" {
  vpc_id     = format("vpc-synth-%s", "15")
  cidr_block = cidrsubnet("10.15.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "15") })
}

resource "aws_iam_role" "synth_16" {
  name = format("vantage-synth-role-%s", "16")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "16")
    idx  = 16
  })
}

resource "aws_subnet" "synth_16" {
  vpc_id     = format("vpc-synth-%s", "16")
  cidr_block = cidrsubnet("10.16.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "16") })
}

resource "aws_iam_role" "synth_17" {
  name = format("vantage-synth-role-%s", "17")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "17")
    idx  = 17
  })
}

resource "aws_subnet" "synth_17" {
  vpc_id     = format("vpc-synth-%s", "17")
  cidr_block = cidrsubnet("10.17.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "17") })
}

resource "aws_iam_role" "synth_18" {
  name = format("vantage-synth-role-%s", "18")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "18")
    idx  = 18
  })
}

resource "aws_subnet" "synth_18" {
  vpc_id     = format("vpc-synth-%s", "18")
  cidr_block = cidrsubnet("10.18.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "18") })
}

resource "aws_iam_role" "synth_19" {
  name = format("vantage-synth-role-%s", "19")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "19")
    idx  = 19
  })
}

resource "aws_subnet" "synth_19" {
  vpc_id     = format("vpc-synth-%s", "19")
  cidr_block = cidrsubnet("10.19.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "19") })
}

resource "aws_iam_role" "synth_20" {
  name = format("vantage-synth-role-%s", "20")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "20")
    idx  = 20
  })
}

resource "aws_subnet" "synth_20" {
  vpc_id     = format("vpc-synth-%s", "20")
  cidr_block = cidrsubnet("10.20.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "20") })
}

resource "aws_iam_role" "synth_21" {
  name = format("vantage-synth-role-%s", "21")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "21")
    idx  = 21
  })
}

resource "aws_subnet" "synth_21" {
  vpc_id     = format("vpc-synth-%s", "21")
  cidr_block = cidrsubnet("10.21.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "21") })
}

resource "aws_iam_role" "synth_22" {
  name = format("vantage-synth-role-%s", "22")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "22")
    idx  = 22
  })
}

resource "aws_subnet" "synth_22" {
  vpc_id     = format("vpc-synth-%s", "22")
  cidr_block = cidrsubnet("10.22.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "22") })
}

resource "aws_iam_role" "synth_23" {
  name = format("vantage-synth-role-%s", "23")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "23")
    idx  = 23
  })
}

resource "aws_subnet" "synth_23" {
  vpc_id     = format("vpc-synth-%s", "23")
  cidr_block = cidrsubnet("10.23.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "23") })
}

resource "aws_iam_role" "synth_24" {
  name = format("vantage-synth-role-%s", "24")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "24")
    idx  = 24
  })
}

resource "aws_subnet" "synth_24" {
  vpc_id     = format("vpc-synth-%s", "24")
  cidr_block = cidrsubnet("10.24.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "24") })
}

resource "aws_iam_role" "synth_25" {
  name = format("vantage-synth-role-%s", "25")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "25")
    idx  = 25
  })
}

resource "aws_subnet" "synth_25" {
  vpc_id     = format("vpc-synth-%s", "25")
  cidr_block = cidrsubnet("10.25.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "25") })
}

resource "aws_iam_role" "synth_26" {
  name = format("vantage-synth-role-%s", "26")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "26")
    idx  = 26
  })
}

resource "aws_subnet" "synth_26" {
  vpc_id     = format("vpc-synth-%s", "26")
  cidr_block = cidrsubnet("10.26.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "26") })
}

resource "aws_iam_role" "synth_27" {
  name = format("vantage-synth-role-%s", "27")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "27")
    idx  = 27
  })
}

resource "aws_subnet" "synth_27" {
  vpc_id     = format("vpc-synth-%s", "27")
  cidr_block = cidrsubnet("10.27.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "27") })
}

resource "aws_iam_role" "synth_28" {
  name = format("vantage-synth-role-%s", "28")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "28")
    idx  = 28
  })
}

resource "aws_subnet" "synth_28" {
  vpc_id     = format("vpc-synth-%s", "28")
  cidr_block = cidrsubnet("10.28.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "28") })
}

resource "aws_iam_role" "synth_29" {
  name = format("vantage-synth-role-%s", "29")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "29")
    idx  = 29
  })
}

resource "aws_subnet" "synth_29" {
  vpc_id     = format("vpc-synth-%s", "29")
  cidr_block = cidrsubnet("10.29.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "29") })
}

resource "aws_iam_role" "synth_30" {
  name = format("vantage-synth-role-%s", "30")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "30")
    idx  = 30
  })
}

resource "aws_subnet" "synth_30" {
  vpc_id     = format("vpc-synth-%s", "30")
  cidr_block = cidrsubnet("10.30.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "30") })
}

resource "aws_iam_role" "synth_31" {
  name = format("vantage-synth-role-%s", "31")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "31")
    idx  = 31
  })
}

resource "aws_subnet" "synth_31" {
  vpc_id     = format("vpc-synth-%s", "31")
  cidr_block = cidrsubnet("10.31.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "31") })
}

resource "aws_iam_role" "synth_32" {
  name = format("vantage-synth-role-%s", "32")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "32")
    idx  = 32
  })
}

resource "aws_subnet" "synth_32" {
  vpc_id     = format("vpc-synth-%s", "32")
  cidr_block = cidrsubnet("10.32.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "32") })
}

resource "aws_iam_role" "synth_33" {
  name = format("vantage-synth-role-%s", "33")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "33")
    idx  = 33
  })
}

resource "aws_subnet" "synth_33" {
  vpc_id     = format("vpc-synth-%s", "33")
  cidr_block = cidrsubnet("10.33.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "33") })
}

resource "aws_iam_role" "synth_34" {
  name = format("vantage-synth-role-%s", "34")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "34")
    idx  = 34
  })
}

resource "aws_subnet" "synth_34" {
  vpc_id     = format("vpc-synth-%s", "34")
  cidr_block = cidrsubnet("10.34.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "34") })
}

resource "aws_iam_role" "synth_35" {
  name = format("vantage-synth-role-%s", "35")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "35")
    idx  = 35
  })
}

resource "aws_subnet" "synth_35" {
  vpc_id     = format("vpc-synth-%s", "35")
  cidr_block = cidrsubnet("10.35.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "35") })
}

resource "aws_iam_role" "synth_36" {
  name = format("vantage-synth-role-%s", "36")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "36")
    idx  = 36
  })
}

resource "aws_subnet" "synth_36" {
  vpc_id     = format("vpc-synth-%s", "36")
  cidr_block = cidrsubnet("10.36.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "36") })
}

resource "aws_iam_role" "synth_37" {
  name = format("vantage-synth-role-%s", "37")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "37")
    idx  = 37
  })
}

resource "aws_subnet" "synth_37" {
  vpc_id     = format("vpc-synth-%s", "37")
  cidr_block = cidrsubnet("10.37.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "37") })
}

resource "aws_iam_role" "synth_38" {
  name = format("vantage-synth-role-%s", "38")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "38")
    idx  = 38
  })
}

resource "aws_subnet" "synth_38" {
  vpc_id     = format("vpc-synth-%s", "38")
  cidr_block = cidrsubnet("10.38.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "38") })
}

resource "aws_iam_role" "synth_39" {
  name = format("vantage-synth-role-%s", "39")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "39")
    idx  = 39
  })
}

resource "aws_subnet" "synth_39" {
  vpc_id     = format("vpc-synth-%s", "39")
  cidr_block = cidrsubnet("10.39.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "39") })
}

resource "aws_iam_role" "synth_40" {
  name = format("vantage-synth-role-%s", "40")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "40")
    idx  = 40
  })
}

resource "aws_subnet" "synth_40" {
  vpc_id     = format("vpc-synth-%s", "40")
  cidr_block = cidrsubnet("10.40.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "40") })
}

resource "aws_iam_role" "synth_41" {
  name = format("vantage-synth-role-%s", "41")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "41")
    idx  = 41
  })
}

resource "aws_subnet" "synth_41" {
  vpc_id     = format("vpc-synth-%s", "41")
  cidr_block = cidrsubnet("10.41.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "41") })
}

resource "aws_iam_role" "synth_42" {
  name = format("vantage-synth-role-%s", "42")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "42")
    idx  = 42
  })
}

resource "aws_subnet" "synth_42" {
  vpc_id     = format("vpc-synth-%s", "42")
  cidr_block = cidrsubnet("10.42.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "42") })
}

resource "aws_iam_role" "synth_43" {
  name = format("vantage-synth-role-%s", "43")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "43")
    idx  = 43
  })
}

resource "aws_subnet" "synth_43" {
  vpc_id     = format("vpc-synth-%s", "43")
  cidr_block = cidrsubnet("10.43.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "43") })
}

resource "aws_iam_role" "synth_44" {
  name = format("vantage-synth-role-%s", "44")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "44")
    idx  = 44
  })
}

resource "aws_subnet" "synth_44" {
  vpc_id     = format("vpc-synth-%s", "44")
  cidr_block = cidrsubnet("10.44.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "44") })
}

resource "aws_iam_role" "synth_45" {
  name = format("vantage-synth-role-%s", "45")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "45")
    idx  = 45
  })
}

resource "aws_subnet" "synth_45" {
  vpc_id     = format("vpc-synth-%s", "45")
  cidr_block = cidrsubnet("10.45.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "45") })
}

resource "aws_iam_role" "synth_46" {
  name = format("vantage-synth-role-%s", "46")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "46")
    idx  = 46
  })
}

resource "aws_subnet" "synth_46" {
  vpc_id     = format("vpc-synth-%s", "46")
  cidr_block = cidrsubnet("10.46.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "46") })
}

resource "aws_iam_role" "synth_47" {
  name = format("vantage-synth-role-%s", "47")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "47")
    idx  = 47
  })
}

resource "aws_subnet" "synth_47" {
  vpc_id     = format("vpc-synth-%s", "47")
  cidr_block = cidrsubnet("10.47.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "47") })
}

resource "aws_iam_role" "synth_48" {
  name = format("vantage-synth-role-%s", "48")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "48")
    idx  = 48
  })
}

resource "aws_subnet" "synth_48" {
  vpc_id     = format("vpc-synth-%s", "48")
  cidr_block = cidrsubnet("10.48.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "48") })
}

resource "aws_iam_role" "synth_49" {
  name = format("vantage-synth-role-%s", "49")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "49")
    idx  = 49
  })
}

resource "aws_subnet" "synth_49" {
  vpc_id     = format("vpc-synth-%s", "49")
  cidr_block = cidrsubnet("10.49.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "49") })
}

resource "aws_iam_role" "synth_50" {
  name = format("vantage-synth-role-%s", "50")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "50")
    idx  = 50
  })
}

resource "aws_subnet" "synth_50" {
  vpc_id     = format("vpc-synth-%s", "50")
  cidr_block = cidrsubnet("10.50.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "50") })
}

resource "aws_iam_role" "synth_51" {
  name = format("vantage-synth-role-%s", "51")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "51")
    idx  = 51
  })
}

resource "aws_subnet" "synth_51" {
  vpc_id     = format("vpc-synth-%s", "51")
  cidr_block = cidrsubnet("10.51.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "51") })
}

resource "aws_iam_role" "synth_52" {
  name = format("vantage-synth-role-%s", "52")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "52")
    idx  = 52
  })
}

resource "aws_subnet" "synth_52" {
  vpc_id     = format("vpc-synth-%s", "52")
  cidr_block = cidrsubnet("10.52.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "52") })
}

resource "aws_iam_role" "synth_53" {
  name = format("vantage-synth-role-%s", "53")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "53")
    idx  = 53
  })
}

resource "aws_subnet" "synth_53" {
  vpc_id     = format("vpc-synth-%s", "53")
  cidr_block = cidrsubnet("10.53.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "53") })
}

resource "aws_iam_role" "synth_54" {
  name = format("vantage-synth-role-%s", "54")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "54")
    idx  = 54
  })
}

resource "aws_subnet" "synth_54" {
  vpc_id     = format("vpc-synth-%s", "54")
  cidr_block = cidrsubnet("10.54.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "54") })
}

resource "aws_iam_role" "synth_55" {
  name = format("vantage-synth-role-%s", "55")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "55")
    idx  = 55
  })
}

resource "aws_subnet" "synth_55" {
  vpc_id     = format("vpc-synth-%s", "55")
  cidr_block = cidrsubnet("10.55.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "55") })
}

resource "aws_iam_role" "synth_56" {
  name = format("vantage-synth-role-%s", "56")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "56")
    idx  = 56
  })
}

resource "aws_subnet" "synth_56" {
  vpc_id     = format("vpc-synth-%s", "56")
  cidr_block = cidrsubnet("10.56.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "56") })
}

resource "aws_iam_role" "synth_57" {
  name = format("vantage-synth-role-%s", "57")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "57")
    idx  = 57
  })
}

resource "aws_subnet" "synth_57" {
  vpc_id     = format("vpc-synth-%s", "57")
  cidr_block = cidrsubnet("10.57.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "57") })
}

resource "aws_iam_role" "synth_58" {
  name = format("vantage-synth-role-%s", "58")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "58")
    idx  = 58
  })
}

resource "aws_subnet" "synth_58" {
  vpc_id     = format("vpc-synth-%s", "58")
  cidr_block = cidrsubnet("10.58.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "58") })
}

resource "aws_iam_role" "synth_59" {
  name = format("vantage-synth-role-%s", "59")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "59")
    idx  = 59
  })
}

resource "aws_subnet" "synth_59" {
  vpc_id     = format("vpc-synth-%s", "59")
  cidr_block = cidrsubnet("10.59.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "59") })
}

resource "aws_iam_role" "synth_60" {
  name = format("vantage-synth-role-%s", "60")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "60")
    idx  = 60
  })
}

resource "aws_subnet" "synth_60" {
  vpc_id     = format("vpc-synth-%s", "60")
  cidr_block = cidrsubnet("10.60.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "60") })
}

resource "aws_iam_role" "synth_61" {
  name = format("vantage-synth-role-%s", "61")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "61")
    idx  = 61
  })
}

resource "aws_subnet" "synth_61" {
  vpc_id     = format("vpc-synth-%s", "61")
  cidr_block = cidrsubnet("10.61.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "61") })
}

resource "aws_iam_role" "synth_62" {
  name = format("vantage-synth-role-%s", "62")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "62")
    idx  = 62
  })
}

resource "aws_subnet" "synth_62" {
  vpc_id     = format("vpc-synth-%s", "62")
  cidr_block = cidrsubnet("10.62.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "62") })
}

resource "aws_iam_role" "synth_63" {
  name = format("vantage-synth-role-%s", "63")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "63")
    idx  = 63
  })
}

resource "aws_subnet" "synth_63" {
  vpc_id     = format("vpc-synth-%s", "63")
  cidr_block = cidrsubnet("10.63.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "63") })
}

resource "aws_iam_role" "synth_64" {
  name = format("vantage-synth-role-%s", "64")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "64")
    idx  = 64
  })
}

resource "aws_subnet" "synth_64" {
  vpc_id     = format("vpc-synth-%s", "64")
  cidr_block = cidrsubnet("10.64.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "64") })
}

resource "aws_iam_role" "synth_65" {
  name = format("vantage-synth-role-%s", "65")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "65")
    idx  = 65
  })
}

resource "aws_subnet" "synth_65" {
  vpc_id     = format("vpc-synth-%s", "65")
  cidr_block = cidrsubnet("10.65.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "65") })
}

resource "aws_iam_role" "synth_66" {
  name = format("vantage-synth-role-%s", "66")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "66")
    idx  = 66
  })
}

resource "aws_subnet" "synth_66" {
  vpc_id     = format("vpc-synth-%s", "66")
  cidr_block = cidrsubnet("10.66.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "66") })
}

resource "aws_iam_role" "synth_67" {
  name = format("vantage-synth-role-%s", "67")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "67")
    idx  = 67
  })
}

resource "aws_subnet" "synth_67" {
  vpc_id     = format("vpc-synth-%s", "67")
  cidr_block = cidrsubnet("10.67.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "67") })
}

resource "aws_iam_role" "synth_68" {
  name = format("vantage-synth-role-%s", "68")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "68")
    idx  = 68
  })
}

resource "aws_subnet" "synth_68" {
  vpc_id     = format("vpc-synth-%s", "68")
  cidr_block = cidrsubnet("10.68.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "68") })
}

resource "aws_iam_role" "synth_69" {
  name = format("vantage-synth-role-%s", "69")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "69")
    idx  = 69
  })
}

resource "aws_subnet" "synth_69" {
  vpc_id     = format("vpc-synth-%s", "69")
  cidr_block = cidrsubnet("10.69.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "69") })
}

resource "aws_iam_role" "synth_70" {
  name = format("vantage-synth-role-%s", "70")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "70")
    idx  = 70
  })
}

resource "aws_subnet" "synth_70" {
  vpc_id     = format("vpc-synth-%s", "70")
  cidr_block = cidrsubnet("10.70.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "70") })
}

resource "aws_iam_role" "synth_71" {
  name = format("vantage-synth-role-%s", "71")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "71")
    idx  = 71
  })
}

resource "aws_subnet" "synth_71" {
  vpc_id     = format("vpc-synth-%s", "71")
  cidr_block = cidrsubnet("10.71.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "71") })
}

resource "aws_iam_role" "synth_72" {
  name = format("vantage-synth-role-%s", "72")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "72")
    idx  = 72
  })
}

resource "aws_subnet" "synth_72" {
  vpc_id     = format("vpc-synth-%s", "72")
  cidr_block = cidrsubnet("10.72.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "72") })
}

resource "aws_iam_role" "synth_73" {
  name = format("vantage-synth-role-%s", "73")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "73")
    idx  = 73
  })
}

resource "aws_subnet" "synth_73" {
  vpc_id     = format("vpc-synth-%s", "73")
  cidr_block = cidrsubnet("10.73.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "73") })
}

resource "aws_iam_role" "synth_74" {
  name = format("vantage-synth-role-%s", "74")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "74")
    idx  = 74
  })
}

resource "aws_subnet" "synth_74" {
  vpc_id     = format("vpc-synth-%s", "74")
  cidr_block = cidrsubnet("10.74.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "74") })
}

resource "aws_iam_role" "synth_75" {
  name = format("vantage-synth-role-%s", "75")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "75")
    idx  = 75
  })
}

resource "aws_subnet" "synth_75" {
  vpc_id     = format("vpc-synth-%s", "75")
  cidr_block = cidrsubnet("10.75.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "75") })
}

resource "aws_iam_role" "synth_76" {
  name = format("vantage-synth-role-%s", "76")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "76")
    idx  = 76
  })
}

resource "aws_subnet" "synth_76" {
  vpc_id     = format("vpc-synth-%s", "76")
  cidr_block = cidrsubnet("10.76.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "76") })
}

resource "aws_iam_role" "synth_77" {
  name = format("vantage-synth-role-%s", "77")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "77")
    idx  = 77
  })
}

resource "aws_subnet" "synth_77" {
  vpc_id     = format("vpc-synth-%s", "77")
  cidr_block = cidrsubnet("10.77.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "77") })
}

resource "aws_iam_role" "synth_78" {
  name = format("vantage-synth-role-%s", "78")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "78")
    idx  = 78
  })
}

resource "aws_subnet" "synth_78" {
  vpc_id     = format("vpc-synth-%s", "78")
  cidr_block = cidrsubnet("10.78.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "78") })
}

resource "aws_iam_role" "synth_79" {
  name = format("vantage-synth-role-%s", "79")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "79")
    idx  = 79
  })
}

resource "aws_subnet" "synth_79" {
  vpc_id     = format("vpc-synth-%s", "79")
  cidr_block = cidrsubnet("10.79.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "79") })
}

resource "aws_iam_role" "synth_80" {
  name = format("vantage-synth-role-%s", "80")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "80")
    idx  = 80
  })
}

resource "aws_subnet" "synth_80" {
  vpc_id     = format("vpc-synth-%s", "80")
  cidr_block = cidrsubnet("10.80.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "80") })
}

resource "aws_iam_role" "synth_81" {
  name = format("vantage-synth-role-%s", "81")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "81")
    idx  = 81
  })
}

resource "aws_subnet" "synth_81" {
  vpc_id     = format("vpc-synth-%s", "81")
  cidr_block = cidrsubnet("10.81.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "81") })
}

resource "aws_iam_role" "synth_82" {
  name = format("vantage-synth-role-%s", "82")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "82")
    idx  = 82
  })
}

resource "aws_subnet" "synth_82" {
  vpc_id     = format("vpc-synth-%s", "82")
  cidr_block = cidrsubnet("10.82.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "82") })
}

resource "aws_iam_role" "synth_83" {
  name = format("vantage-synth-role-%s", "83")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "83")
    idx  = 83
  })
}

resource "aws_subnet" "synth_83" {
  vpc_id     = format("vpc-synth-%s", "83")
  cidr_block = cidrsubnet("10.83.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "83") })
}

resource "aws_iam_role" "synth_84" {
  name = format("vantage-synth-role-%s", "84")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "84")
    idx  = 84
  })
}

resource "aws_subnet" "synth_84" {
  vpc_id     = format("vpc-synth-%s", "84")
  cidr_block = cidrsubnet("10.84.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "84") })
}

resource "aws_iam_role" "synth_85" {
  name = format("vantage-synth-role-%s", "85")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "85")
    idx  = 85
  })
}

resource "aws_subnet" "synth_85" {
  vpc_id     = format("vpc-synth-%s", "85")
  cidr_block = cidrsubnet("10.85.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "85") })
}

resource "aws_iam_role" "synth_86" {
  name = format("vantage-synth-role-%s", "86")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "86")
    idx  = 86
  })
}

resource "aws_subnet" "synth_86" {
  vpc_id     = format("vpc-synth-%s", "86")
  cidr_block = cidrsubnet("10.86.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "86") })
}

resource "aws_iam_role" "synth_87" {
  name = format("vantage-synth-role-%s", "87")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "87")
    idx  = 87
  })
}

resource "aws_subnet" "synth_87" {
  vpc_id     = format("vpc-synth-%s", "87")
  cidr_block = cidrsubnet("10.87.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "87") })
}

resource "aws_iam_role" "synth_88" {
  name = format("vantage-synth-role-%s", "88")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "88")
    idx  = 88
  })
}

resource "aws_subnet" "synth_88" {
  vpc_id     = format("vpc-synth-%s", "88")
  cidr_block = cidrsubnet("10.88.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "88") })
}

resource "aws_iam_role" "synth_89" {
  name = format("vantage-synth-role-%s", "89")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "89")
    idx  = 89
  })
}

resource "aws_subnet" "synth_89" {
  vpc_id     = format("vpc-synth-%s", "89")
  cidr_block = cidrsubnet("10.89.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "89") })
}

resource "aws_iam_role" "synth_90" {
  name = format("vantage-synth-role-%s", "90")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "90")
    idx  = 90
  })
}

resource "aws_subnet" "synth_90" {
  vpc_id     = format("vpc-synth-%s", "90")
  cidr_block = cidrsubnet("10.90.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "90") })
}

resource "aws_iam_role" "synth_91" {
  name = format("vantage-synth-role-%s", "91")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "91")
    idx  = 91
  })
}

resource "aws_subnet" "synth_91" {
  vpc_id     = format("vpc-synth-%s", "91")
  cidr_block = cidrsubnet("10.91.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "91") })
}

resource "aws_iam_role" "synth_92" {
  name = format("vantage-synth-role-%s", "92")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "92")
    idx  = 92
  })
}

resource "aws_subnet" "synth_92" {
  vpc_id     = format("vpc-synth-%s", "92")
  cidr_block = cidrsubnet("10.92.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "92") })
}

resource "aws_iam_role" "synth_93" {
  name = format("vantage-synth-role-%s", "93")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "93")
    idx  = 93
  })
}

resource "aws_subnet" "synth_93" {
  vpc_id     = format("vpc-synth-%s", "93")
  cidr_block = cidrsubnet("10.93.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "93") })
}

resource "aws_iam_role" "synth_94" {
  name = format("vantage-synth-role-%s", "94")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "94")
    idx  = 94
  })
}

resource "aws_subnet" "synth_94" {
  vpc_id     = format("vpc-synth-%s", "94")
  cidr_block = cidrsubnet("10.94.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "94") })
}

resource "aws_iam_role" "synth_95" {
  name = format("vantage-synth-role-%s", "95")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "95")
    idx  = 95
  })
}

resource "aws_subnet" "synth_95" {
  vpc_id     = format("vpc-synth-%s", "95")
  cidr_block = cidrsubnet("10.95.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "95") })
}

resource "aws_iam_role" "synth_96" {
  name = format("vantage-synth-role-%s", "96")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "96")
    idx  = 96
  })
}

resource "aws_subnet" "synth_96" {
  vpc_id     = format("vpc-synth-%s", "96")
  cidr_block = cidrsubnet("10.96.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "96") })
}

resource "aws_iam_role" "synth_97" {
  name = format("vantage-synth-role-%s", "97")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "97")
    idx  = 97
  })
}

resource "aws_subnet" "synth_97" {
  vpc_id     = format("vpc-synth-%s", "97")
  cidr_block = cidrsubnet("10.97.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "97") })
}

resource "aws_iam_role" "synth_98" {
  name = format("vantage-synth-role-%s", "98")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "98")
    idx  = 98
  })
}

resource "aws_subnet" "synth_98" {
  vpc_id     = format("vpc-synth-%s", "98")
  cidr_block = cidrsubnet("10.98.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "98") })
}

resource "aws_iam_role" "synth_99" {
  name = format("vantage-synth-role-%s", "99")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "99")
    idx  = 99
  })
}

resource "aws_subnet" "synth_99" {
  vpc_id     = format("vpc-synth-%s", "99")
  cidr_block = cidrsubnet("10.99.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "99") })
}

resource "aws_iam_role" "synth_100" {
  name = format("vantage-synth-role-%s", "100")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "100")
    idx  = 100
  })
}

resource "aws_subnet" "synth_100" {
  vpc_id     = format("vpc-synth-%s", "100")
  cidr_block = cidrsubnet("10.100.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "100") })
}

resource "aws_iam_role" "synth_101" {
  name = format("vantage-synth-role-%s", "101")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "101")
    idx  = 101
  })
}

resource "aws_subnet" "synth_101" {
  vpc_id     = format("vpc-synth-%s", "101")
  cidr_block = cidrsubnet("10.101.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "101") })
}

resource "aws_iam_role" "synth_102" {
  name = format("vantage-synth-role-%s", "102")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "102")
    idx  = 102
  })
}

resource "aws_subnet" "synth_102" {
  vpc_id     = format("vpc-synth-%s", "102")
  cidr_block = cidrsubnet("10.102.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "102") })
}

resource "aws_iam_role" "synth_103" {
  name = format("vantage-synth-role-%s", "103")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "103")
    idx  = 103
  })
}

resource "aws_subnet" "synth_103" {
  vpc_id     = format("vpc-synth-%s", "103")
  cidr_block = cidrsubnet("10.103.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "103") })
}

resource "aws_iam_role" "synth_104" {
  name = format("vantage-synth-role-%s", "104")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "104")
    idx  = 104
  })
}

resource "aws_subnet" "synth_104" {
  vpc_id     = format("vpc-synth-%s", "104")
  cidr_block = cidrsubnet("10.104.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "104") })
}

resource "aws_iam_role" "synth_105" {
  name = format("vantage-synth-role-%s", "105")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "105")
    idx  = 105
  })
}

resource "aws_subnet" "synth_105" {
  vpc_id     = format("vpc-synth-%s", "105")
  cidr_block = cidrsubnet("10.105.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "105") })
}

resource "aws_iam_role" "synth_106" {
  name = format("vantage-synth-role-%s", "106")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "106")
    idx  = 106
  })
}

resource "aws_subnet" "synth_106" {
  vpc_id     = format("vpc-synth-%s", "106")
  cidr_block = cidrsubnet("10.106.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "106") })
}

resource "aws_iam_role" "synth_107" {
  name = format("vantage-synth-role-%s", "107")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "107")
    idx  = 107
  })
}

resource "aws_subnet" "synth_107" {
  vpc_id     = format("vpc-synth-%s", "107")
  cidr_block = cidrsubnet("10.107.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "107") })
}

resource "aws_iam_role" "synth_108" {
  name = format("vantage-synth-role-%s", "108")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "108")
    idx  = 108
  })
}

resource "aws_subnet" "synth_108" {
  vpc_id     = format("vpc-synth-%s", "108")
  cidr_block = cidrsubnet("10.108.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "108") })
}

resource "aws_iam_role" "synth_109" {
  name = format("vantage-synth-role-%s", "109")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "109")
    idx  = 109
  })
}

resource "aws_subnet" "synth_109" {
  vpc_id     = format("vpc-synth-%s", "109")
  cidr_block = cidrsubnet("10.109.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "109") })
}

resource "aws_iam_role" "synth_110" {
  name = format("vantage-synth-role-%s", "110")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "110")
    idx  = 110
  })
}

resource "aws_subnet" "synth_110" {
  vpc_id     = format("vpc-synth-%s", "110")
  cidr_block = cidrsubnet("10.110.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "110") })
}

resource "aws_iam_role" "synth_111" {
  name = format("vantage-synth-role-%s", "111")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "111")
    idx  = 111
  })
}

resource "aws_subnet" "synth_111" {
  vpc_id     = format("vpc-synth-%s", "111")
  cidr_block = cidrsubnet("10.111.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "111") })
}

resource "aws_iam_role" "synth_112" {
  name = format("vantage-synth-role-%s", "112")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "112")
    idx  = 112
  })
}

resource "aws_subnet" "synth_112" {
  vpc_id     = format("vpc-synth-%s", "112")
  cidr_block = cidrsubnet("10.112.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "112") })
}

resource "aws_iam_role" "synth_113" {
  name = format("vantage-synth-role-%s", "113")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "113")
    idx  = 113
  })
}

resource "aws_subnet" "synth_113" {
  vpc_id     = format("vpc-synth-%s", "113")
  cidr_block = cidrsubnet("10.113.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "113") })
}

resource "aws_iam_role" "synth_114" {
  name = format("vantage-synth-role-%s", "114")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "114")
    idx  = 114
  })
}

resource "aws_subnet" "synth_114" {
  vpc_id     = format("vpc-synth-%s", "114")
  cidr_block = cidrsubnet("10.114.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "114") })
}

resource "aws_iam_role" "synth_115" {
  name = format("vantage-synth-role-%s", "115")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "115")
    idx  = 115
  })
}

resource "aws_subnet" "synth_115" {
  vpc_id     = format("vpc-synth-%s", "115")
  cidr_block = cidrsubnet("10.115.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "115") })
}

resource "aws_iam_role" "synth_116" {
  name = format("vantage-synth-role-%s", "116")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "116")
    idx  = 116
  })
}

resource "aws_subnet" "synth_116" {
  vpc_id     = format("vpc-synth-%s", "116")
  cidr_block = cidrsubnet("10.116.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "116") })
}

resource "aws_iam_role" "synth_117" {
  name = format("vantage-synth-role-%s", "117")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "117")
    idx  = 117
  })
}

resource "aws_subnet" "synth_117" {
  vpc_id     = format("vpc-synth-%s", "117")
  cidr_block = cidrsubnet("10.117.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "117") })
}

resource "aws_iam_role" "synth_118" {
  name = format("vantage-synth-role-%s", "118")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "118")
    idx  = 118
  })
}

resource "aws_subnet" "synth_118" {
  vpc_id     = format("vpc-synth-%s", "118")
  cidr_block = cidrsubnet("10.118.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "118") })
}

resource "aws_iam_role" "synth_119" {
  name = format("vantage-synth-role-%s", "119")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "119")
    idx  = 119
  })
}

resource "aws_subnet" "synth_119" {
  vpc_id     = format("vpc-synth-%s", "119")
  cidr_block = cidrsubnet("10.119.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "119") })
}

resource "aws_iam_role" "synth_120" {
  name = format("vantage-synth-role-%s", "120")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "120")
    idx  = 120
  })
}

resource "aws_subnet" "synth_120" {
  vpc_id     = format("vpc-synth-%s", "120")
  cidr_block = cidrsubnet("10.120.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "120") })
}

resource "aws_iam_role" "synth_121" {
  name = format("vantage-synth-role-%s", "121")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "121")
    idx  = 121
  })
}

resource "aws_subnet" "synth_121" {
  vpc_id     = format("vpc-synth-%s", "121")
  cidr_block = cidrsubnet("10.121.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "121") })
}

resource "aws_iam_role" "synth_122" {
  name = format("vantage-synth-role-%s", "122")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "122")
    idx  = 122
  })
}

resource "aws_subnet" "synth_122" {
  vpc_id     = format("vpc-synth-%s", "122")
  cidr_block = cidrsubnet("10.122.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "122") })
}

resource "aws_iam_role" "synth_123" {
  name = format("vantage-synth-role-%s", "123")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "123")
    idx  = 123
  })
}

resource "aws_subnet" "synth_123" {
  vpc_id     = format("vpc-synth-%s", "123")
  cidr_block = cidrsubnet("10.123.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "123") })
}

resource "aws_iam_role" "synth_124" {
  name = format("vantage-synth-role-%s", "124")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "124")
    idx  = 124
  })
}

resource "aws_subnet" "synth_124" {
  vpc_id     = format("vpc-synth-%s", "124")
  cidr_block = cidrsubnet("10.124.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "124") })
}

resource "aws_iam_role" "synth_125" {
  name = format("vantage-synth-role-%s", "125")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "125")
    idx  = 125
  })
}

resource "aws_subnet" "synth_125" {
  vpc_id     = format("vpc-synth-%s", "125")
  cidr_block = cidrsubnet("10.125.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "125") })
}

resource "aws_iam_role" "synth_126" {
  name = format("vantage-synth-role-%s", "126")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "126")
    idx  = 126
  })
}

resource "aws_subnet" "synth_126" {
  vpc_id     = format("vpc-synth-%s", "126")
  cidr_block = cidrsubnet("10.126.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "126") })
}

resource "aws_iam_role" "synth_127" {
  name = format("vantage-synth-role-%s", "127")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "127")
    idx  = 127
  })
}

resource "aws_subnet" "synth_127" {
  vpc_id     = format("vpc-synth-%s", "127")
  cidr_block = cidrsubnet("10.127.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "127") })
}

resource "aws_iam_role" "synth_128" {
  name = format("vantage-synth-role-%s", "128")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "128")
    idx  = 128
  })
}

resource "aws_subnet" "synth_128" {
  vpc_id     = format("vpc-synth-%s", "128")
  cidr_block = cidrsubnet("10.128.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "128") })
}

resource "aws_iam_role" "synth_129" {
  name = format("vantage-synth-role-%s", "129")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "129")
    idx  = 129
  })
}

resource "aws_subnet" "synth_129" {
  vpc_id     = format("vpc-synth-%s", "129")
  cidr_block = cidrsubnet("10.129.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "129") })
}

resource "aws_iam_role" "synth_130" {
  name = format("vantage-synth-role-%s", "130")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "130")
    idx  = 130
  })
}

resource "aws_subnet" "synth_130" {
  vpc_id     = format("vpc-synth-%s", "130")
  cidr_block = cidrsubnet("10.130.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "130") })
}

resource "aws_iam_role" "synth_131" {
  name = format("vantage-synth-role-%s", "131")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "131")
    idx  = 131
  })
}

resource "aws_subnet" "synth_131" {
  vpc_id     = format("vpc-synth-%s", "131")
  cidr_block = cidrsubnet("10.131.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "131") })
}

resource "aws_iam_role" "synth_132" {
  name = format("vantage-synth-role-%s", "132")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "132")
    idx  = 132
  })
}

resource "aws_subnet" "synth_132" {
  vpc_id     = format("vpc-synth-%s", "132")
  cidr_block = cidrsubnet("10.132.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "132") })
}

resource "aws_iam_role" "synth_133" {
  name = format("vantage-synth-role-%s", "133")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "133")
    idx  = 133
  })
}

resource "aws_subnet" "synth_133" {
  vpc_id     = format("vpc-synth-%s", "133")
  cidr_block = cidrsubnet("10.133.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "133") })
}

resource "aws_iam_role" "synth_134" {
  name = format("vantage-synth-role-%s", "134")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "134")
    idx  = 134
  })
}

resource "aws_subnet" "synth_134" {
  vpc_id     = format("vpc-synth-%s", "134")
  cidr_block = cidrsubnet("10.134.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "134") })
}

resource "aws_iam_role" "synth_135" {
  name = format("vantage-synth-role-%s", "135")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "135")
    idx  = 135
  })
}

resource "aws_subnet" "synth_135" {
  vpc_id     = format("vpc-synth-%s", "135")
  cidr_block = cidrsubnet("10.135.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "135") })
}

resource "aws_iam_role" "synth_136" {
  name = format("vantage-synth-role-%s", "136")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "136")
    idx  = 136
  })
}

resource "aws_subnet" "synth_136" {
  vpc_id     = format("vpc-synth-%s", "136")
  cidr_block = cidrsubnet("10.136.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "136") })
}

resource "aws_iam_role" "synth_137" {
  name = format("vantage-synth-role-%s", "137")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "137")
    idx  = 137
  })
}

resource "aws_subnet" "synth_137" {
  vpc_id     = format("vpc-synth-%s", "137")
  cidr_block = cidrsubnet("10.137.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "137") })
}

resource "aws_iam_role" "synth_138" {
  name = format("vantage-synth-role-%s", "138")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "138")
    idx  = 138
  })
}

resource "aws_subnet" "synth_138" {
  vpc_id     = format("vpc-synth-%s", "138")
  cidr_block = cidrsubnet("10.138.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "138") })
}

resource "aws_iam_role" "synth_139" {
  name = format("vantage-synth-role-%s", "139")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "139")
    idx  = 139
  })
}

resource "aws_subnet" "synth_139" {
  vpc_id     = format("vpc-synth-%s", "139")
  cidr_block = cidrsubnet("10.139.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "139") })
}

resource "aws_iam_role" "synth_140" {
  name = format("vantage-synth-role-%s", "140")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "140")
    idx  = 140
  })
}

resource "aws_subnet" "synth_140" {
  vpc_id     = format("vpc-synth-%s", "140")
  cidr_block = cidrsubnet("10.140.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "140") })
}

resource "aws_iam_role" "synth_141" {
  name = format("vantage-synth-role-%s", "141")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "141")
    idx  = 141
  })
}

resource "aws_subnet" "synth_141" {
  vpc_id     = format("vpc-synth-%s", "141")
  cidr_block = cidrsubnet("10.141.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "141") })
}

resource "aws_iam_role" "synth_142" {
  name = format("vantage-synth-role-%s", "142")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "142")
    idx  = 142
  })
}

resource "aws_subnet" "synth_142" {
  vpc_id     = format("vpc-synth-%s", "142")
  cidr_block = cidrsubnet("10.142.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "142") })
}

resource "aws_iam_role" "synth_143" {
  name = format("vantage-synth-role-%s", "143")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "143")
    idx  = 143
  })
}

resource "aws_subnet" "synth_143" {
  vpc_id     = format("vpc-synth-%s", "143")
  cidr_block = cidrsubnet("10.143.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "143") })
}

resource "aws_iam_role" "synth_144" {
  name = format("vantage-synth-role-%s", "144")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "144")
    idx  = 144
  })
}

resource "aws_subnet" "synth_144" {
  vpc_id     = format("vpc-synth-%s", "144")
  cidr_block = cidrsubnet("10.144.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "144") })
}

resource "aws_iam_role" "synth_145" {
  name = format("vantage-synth-role-%s", "145")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "145")
    idx  = 145
  })
}

resource "aws_subnet" "synth_145" {
  vpc_id     = format("vpc-synth-%s", "145")
  cidr_block = cidrsubnet("10.145.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "145") })
}

resource "aws_iam_role" "synth_146" {
  name = format("vantage-synth-role-%s", "146")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "146")
    idx  = 146
  })
}

resource "aws_subnet" "synth_146" {
  vpc_id     = format("vpc-synth-%s", "146")
  cidr_block = cidrsubnet("10.146.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "146") })
}

resource "aws_iam_role" "synth_147" {
  name = format("vantage-synth-role-%s", "147")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "147")
    idx  = 147
  })
}

resource "aws_subnet" "synth_147" {
  vpc_id     = format("vpc-synth-%s", "147")
  cidr_block = cidrsubnet("10.147.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "147") })
}

resource "aws_iam_role" "synth_148" {
  name = format("vantage-synth-role-%s", "148")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "148")
    idx  = 148
  })
}

resource "aws_subnet" "synth_148" {
  vpc_id     = format("vpc-synth-%s", "148")
  cidr_block = cidrsubnet("10.148.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "148") })
}

resource "aws_iam_role" "synth_149" {
  name = format("vantage-synth-role-%s", "149")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "149")
    idx  = 149
  })
}

resource "aws_subnet" "synth_149" {
  vpc_id     = format("vpc-synth-%s", "149")
  cidr_block = cidrsubnet("10.149.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "149") })
}

resource "aws_iam_role" "synth_150" {
  name = format("vantage-synth-role-%s", "150")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "150")
    idx  = 150
  })
}

resource "aws_subnet" "synth_150" {
  vpc_id     = format("vpc-synth-%s", "150")
  cidr_block = cidrsubnet("10.150.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "150") })
}

resource "aws_iam_role" "synth_151" {
  name = format("vantage-synth-role-%s", "151")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "151")
    idx  = 151
  })
}

resource "aws_subnet" "synth_151" {
  vpc_id     = format("vpc-synth-%s", "151")
  cidr_block = cidrsubnet("10.151.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "151") })
}

resource "aws_iam_role" "synth_152" {
  name = format("vantage-synth-role-%s", "152")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "152")
    idx  = 152
  })
}

resource "aws_subnet" "synth_152" {
  vpc_id     = format("vpc-synth-%s", "152")
  cidr_block = cidrsubnet("10.152.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "152") })
}

resource "aws_iam_role" "synth_153" {
  name = format("vantage-synth-role-%s", "153")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "153")
    idx  = 153
  })
}

resource "aws_subnet" "synth_153" {
  vpc_id     = format("vpc-synth-%s", "153")
  cidr_block = cidrsubnet("10.153.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "153") })
}

resource "aws_iam_role" "synth_154" {
  name = format("vantage-synth-role-%s", "154")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "154")
    idx  = 154
  })
}

resource "aws_subnet" "synth_154" {
  vpc_id     = format("vpc-synth-%s", "154")
  cidr_block = cidrsubnet("10.154.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "154") })
}

resource "aws_iam_role" "synth_155" {
  name = format("vantage-synth-role-%s", "155")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "155")
    idx  = 155
  })
}

resource "aws_subnet" "synth_155" {
  vpc_id     = format("vpc-synth-%s", "155")
  cidr_block = cidrsubnet("10.155.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "155") })
}

resource "aws_iam_role" "synth_156" {
  name = format("vantage-synth-role-%s", "156")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "156")
    idx  = 156
  })
}

resource "aws_subnet" "synth_156" {
  vpc_id     = format("vpc-synth-%s", "156")
  cidr_block = cidrsubnet("10.156.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "156") })
}

resource "aws_iam_role" "synth_157" {
  name = format("vantage-synth-role-%s", "157")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "157")
    idx  = 157
  })
}

resource "aws_subnet" "synth_157" {
  vpc_id     = format("vpc-synth-%s", "157")
  cidr_block = cidrsubnet("10.157.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "157") })
}

resource "aws_iam_role" "synth_158" {
  name = format("vantage-synth-role-%s", "158")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "158")
    idx  = 158
  })
}

resource "aws_subnet" "synth_158" {
  vpc_id     = format("vpc-synth-%s", "158")
  cidr_block = cidrsubnet("10.158.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "158") })
}

resource "aws_iam_role" "synth_159" {
  name = format("vantage-synth-role-%s", "159")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "159")
    idx  = 159
  })
}

resource "aws_subnet" "synth_159" {
  vpc_id     = format("vpc-synth-%s", "159")
  cidr_block = cidrsubnet("10.159.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "159") })
}

resource "aws_iam_role" "synth_160" {
  name = format("vantage-synth-role-%s", "160")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "160")
    idx  = 160
  })
}

resource "aws_subnet" "synth_160" {
  vpc_id     = format("vpc-synth-%s", "160")
  cidr_block = cidrsubnet("10.160.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "160") })
}

resource "aws_iam_role" "synth_161" {
  name = format("vantage-synth-role-%s", "161")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "161")
    idx  = 161
  })
}

resource "aws_subnet" "synth_161" {
  vpc_id     = format("vpc-synth-%s", "161")
  cidr_block = cidrsubnet("10.161.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "161") })
}

resource "aws_iam_role" "synth_162" {
  name = format("vantage-synth-role-%s", "162")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "162")
    idx  = 162
  })
}

resource "aws_subnet" "synth_162" {
  vpc_id     = format("vpc-synth-%s", "162")
  cidr_block = cidrsubnet("10.162.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "162") })
}

resource "aws_iam_role" "synth_163" {
  name = format("vantage-synth-role-%s", "163")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "163")
    idx  = 163
  })
}

resource "aws_subnet" "synth_163" {
  vpc_id     = format("vpc-synth-%s", "163")
  cidr_block = cidrsubnet("10.163.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "163") })
}

resource "aws_iam_role" "synth_164" {
  name = format("vantage-synth-role-%s", "164")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "164")
    idx  = 164
  })
}

resource "aws_subnet" "synth_164" {
  vpc_id     = format("vpc-synth-%s", "164")
  cidr_block = cidrsubnet("10.164.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "164") })
}

resource "aws_iam_role" "synth_165" {
  name = format("vantage-synth-role-%s", "165")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "165")
    idx  = 165
  })
}

resource "aws_subnet" "synth_165" {
  vpc_id     = format("vpc-synth-%s", "165")
  cidr_block = cidrsubnet("10.165.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "165") })
}

resource "aws_iam_role" "synth_166" {
  name = format("vantage-synth-role-%s", "166")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "166")
    idx  = 166
  })
}

resource "aws_subnet" "synth_166" {
  vpc_id     = format("vpc-synth-%s", "166")
  cidr_block = cidrsubnet("10.166.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "166") })
}

resource "aws_iam_role" "synth_167" {
  name = format("vantage-synth-role-%s", "167")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "167")
    idx  = 167
  })
}

resource "aws_subnet" "synth_167" {
  vpc_id     = format("vpc-synth-%s", "167")
  cidr_block = cidrsubnet("10.167.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "167") })
}

resource "aws_iam_role" "synth_168" {
  name = format("vantage-synth-role-%s", "168")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "168")
    idx  = 168
  })
}

resource "aws_subnet" "synth_168" {
  vpc_id     = format("vpc-synth-%s", "168")
  cidr_block = cidrsubnet("10.168.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "168") })
}

resource "aws_iam_role" "synth_169" {
  name = format("vantage-synth-role-%s", "169")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "169")
    idx  = 169
  })
}

resource "aws_subnet" "synth_169" {
  vpc_id     = format("vpc-synth-%s", "169")
  cidr_block = cidrsubnet("10.169.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "169") })
}

resource "aws_iam_role" "synth_170" {
  name = format("vantage-synth-role-%s", "170")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "170")
    idx  = 170
  })
}

resource "aws_subnet" "synth_170" {
  vpc_id     = format("vpc-synth-%s", "170")
  cidr_block = cidrsubnet("10.170.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "170") })
}

resource "aws_iam_role" "synth_171" {
  name = format("vantage-synth-role-%s", "171")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "171")
    idx  = 171
  })
}

resource "aws_subnet" "synth_171" {
  vpc_id     = format("vpc-synth-%s", "171")
  cidr_block = cidrsubnet("10.171.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "171") })
}

resource "aws_iam_role" "synth_172" {
  name = format("vantage-synth-role-%s", "172")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "172")
    idx  = 172
  })
}

resource "aws_subnet" "synth_172" {
  vpc_id     = format("vpc-synth-%s", "172")
  cidr_block = cidrsubnet("10.172.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "172") })
}

resource "aws_iam_role" "synth_173" {
  name = format("vantage-synth-role-%s", "173")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "173")
    idx  = 173
  })
}

resource "aws_subnet" "synth_173" {
  vpc_id     = format("vpc-synth-%s", "173")
  cidr_block = cidrsubnet("10.173.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "173") })
}

resource "aws_iam_role" "synth_174" {
  name = format("vantage-synth-role-%s", "174")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "174")
    idx  = 174
  })
}

resource "aws_subnet" "synth_174" {
  vpc_id     = format("vpc-synth-%s", "174")
  cidr_block = cidrsubnet("10.174.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "174") })
}

resource "aws_iam_role" "synth_175" {
  name = format("vantage-synth-role-%s", "175")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "175")
    idx  = 175
  })
}

resource "aws_subnet" "synth_175" {
  vpc_id     = format("vpc-synth-%s", "175")
  cidr_block = cidrsubnet("10.175.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "175") })
}

resource "aws_iam_role" "synth_176" {
  name = format("vantage-synth-role-%s", "176")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "176")
    idx  = 176
  })
}

resource "aws_subnet" "synth_176" {
  vpc_id     = format("vpc-synth-%s", "176")
  cidr_block = cidrsubnet("10.176.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "176") })
}

resource "aws_iam_role" "synth_177" {
  name = format("vantage-synth-role-%s", "177")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "177")
    idx  = 177
  })
}

resource "aws_subnet" "synth_177" {
  vpc_id     = format("vpc-synth-%s", "177")
  cidr_block = cidrsubnet("10.177.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "177") })
}

resource "aws_iam_role" "synth_178" {
  name = format("vantage-synth-role-%s", "178")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "178")
    idx  = 178
  })
}

resource "aws_subnet" "synth_178" {
  vpc_id     = format("vpc-synth-%s", "178")
  cidr_block = cidrsubnet("10.178.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "178") })
}

resource "aws_iam_role" "synth_179" {
  name = format("vantage-synth-role-%s", "179")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "179")
    idx  = 179
  })
}

resource "aws_subnet" "synth_179" {
  vpc_id     = format("vpc-synth-%s", "179")
  cidr_block = cidrsubnet("10.179.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "179") })
}

resource "aws_iam_role" "synth_180" {
  name = format("vantage-synth-role-%s", "180")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "180")
    idx  = 180
  })
}

resource "aws_subnet" "synth_180" {
  vpc_id     = format("vpc-synth-%s", "180")
  cidr_block = cidrsubnet("10.180.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "180") })
}

resource "aws_iam_role" "synth_181" {
  name = format("vantage-synth-role-%s", "181")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "181")
    idx  = 181
  })
}

resource "aws_subnet" "synth_181" {
  vpc_id     = format("vpc-synth-%s", "181")
  cidr_block = cidrsubnet("10.181.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "181") })
}

resource "aws_iam_role" "synth_182" {
  name = format("vantage-synth-role-%s", "182")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "182")
    idx  = 182
  })
}

resource "aws_subnet" "synth_182" {
  vpc_id     = format("vpc-synth-%s", "182")
  cidr_block = cidrsubnet("10.182.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "182") })
}

resource "aws_iam_role" "synth_183" {
  name = format("vantage-synth-role-%s", "183")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "183")
    idx  = 183
  })
}

resource "aws_subnet" "synth_183" {
  vpc_id     = format("vpc-synth-%s", "183")
  cidr_block = cidrsubnet("10.183.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "183") })
}

resource "aws_iam_role" "synth_184" {
  name = format("vantage-synth-role-%s", "184")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "184")
    idx  = 184
  })
}

resource "aws_subnet" "synth_184" {
  vpc_id     = format("vpc-synth-%s", "184")
  cidr_block = cidrsubnet("10.184.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "184") })
}

resource "aws_iam_role" "synth_185" {
  name = format("vantage-synth-role-%s", "185")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "185")
    idx  = 185
  })
}

resource "aws_subnet" "synth_185" {
  vpc_id     = format("vpc-synth-%s", "185")
  cidr_block = cidrsubnet("10.185.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "185") })
}

resource "aws_iam_role" "synth_186" {
  name = format("vantage-synth-role-%s", "186")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "186")
    idx  = 186
  })
}

resource "aws_subnet" "synth_186" {
  vpc_id     = format("vpc-synth-%s", "186")
  cidr_block = cidrsubnet("10.186.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "186") })
}

resource "aws_iam_role" "synth_187" {
  name = format("vantage-synth-role-%s", "187")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "187")
    idx  = 187
  })
}

resource "aws_subnet" "synth_187" {
  vpc_id     = format("vpc-synth-%s", "187")
  cidr_block = cidrsubnet("10.187.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "187") })
}

resource "aws_iam_role" "synth_188" {
  name = format("vantage-synth-role-%s", "188")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "188")
    idx  = 188
  })
}

resource "aws_subnet" "synth_188" {
  vpc_id     = format("vpc-synth-%s", "188")
  cidr_block = cidrsubnet("10.188.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "188") })
}

resource "aws_iam_role" "synth_189" {
  name = format("vantage-synth-role-%s", "189")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "189")
    idx  = 189
  })
}

resource "aws_subnet" "synth_189" {
  vpc_id     = format("vpc-synth-%s", "189")
  cidr_block = cidrsubnet("10.189.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "189") })
}

resource "aws_iam_role" "synth_190" {
  name = format("vantage-synth-role-%s", "190")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "190")
    idx  = 190
  })
}

resource "aws_subnet" "synth_190" {
  vpc_id     = format("vpc-synth-%s", "190")
  cidr_block = cidrsubnet("10.190.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "190") })
}

resource "aws_iam_role" "synth_191" {
  name = format("vantage-synth-role-%s", "191")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "191")
    idx  = 191
  })
}

resource "aws_subnet" "synth_191" {
  vpc_id     = format("vpc-synth-%s", "191")
  cidr_block = cidrsubnet("10.191.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "191") })
}

resource "aws_iam_role" "synth_192" {
  name = format("vantage-synth-role-%s", "192")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "192")
    idx  = 192
  })
}

resource "aws_subnet" "synth_192" {
  vpc_id     = format("vpc-synth-%s", "192")
  cidr_block = cidrsubnet("10.192.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "192") })
}

resource "aws_iam_role" "synth_193" {
  name = format("vantage-synth-role-%s", "193")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "193")
    idx  = 193
  })
}

resource "aws_subnet" "synth_193" {
  vpc_id     = format("vpc-synth-%s", "193")
  cidr_block = cidrsubnet("10.193.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "193") })
}

resource "aws_iam_role" "synth_194" {
  name = format("vantage-synth-role-%s", "194")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "194")
    idx  = 194
  })
}

resource "aws_subnet" "synth_194" {
  vpc_id     = format("vpc-synth-%s", "194")
  cidr_block = cidrsubnet("10.194.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "194") })
}

resource "aws_iam_role" "synth_195" {
  name = format("vantage-synth-role-%s", "195")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "195")
    idx  = 195
  })
}

resource "aws_subnet" "synth_195" {
  vpc_id     = format("vpc-synth-%s", "195")
  cidr_block = cidrsubnet("10.195.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "195") })
}

resource "aws_iam_role" "synth_196" {
  name = format("vantage-synth-role-%s", "196")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "196")
    idx  = 196
  })
}

resource "aws_subnet" "synth_196" {
  vpc_id     = format("vpc-synth-%s", "196")
  cidr_block = cidrsubnet("10.196.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "196") })
}

resource "aws_iam_role" "synth_197" {
  name = format("vantage-synth-role-%s", "197")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "197")
    idx  = 197
  })
}

resource "aws_subnet" "synth_197" {
  vpc_id     = format("vpc-synth-%s", "197")
  cidr_block = cidrsubnet("10.197.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "197") })
}

resource "aws_iam_role" "synth_198" {
  name = format("vantage-synth-role-%s", "198")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "198")
    idx  = 198
  })
}

resource "aws_subnet" "synth_198" {
  vpc_id     = format("vpc-synth-%s", "198")
  cidr_block = cidrsubnet("10.198.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "198") })
}

resource "aws_iam_role" "synth_199" {
  name = format("vantage-synth-role-%s", "199")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "199")
    idx  = 199
  })
}

resource "aws_subnet" "synth_199" {
  vpc_id     = format("vpc-synth-%s", "199")
  cidr_block = cidrsubnet("10.199.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "199") })
}

resource "aws_iam_role" "synth_200" {
  name = format("vantage-synth-role-%s", "200")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "200")
    idx  = 200
  })
}

resource "aws_subnet" "synth_200" {
  vpc_id     = format("vpc-synth-%s", "200")
  cidr_block = cidrsubnet("10.0.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "200") })
}

resource "aws_iam_role" "synth_201" {
  name = format("vantage-synth-role-%s", "201")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "201")
    idx  = 201
  })
}

resource "aws_subnet" "synth_201" {
  vpc_id     = format("vpc-synth-%s", "201")
  cidr_block = cidrsubnet("10.1.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "201") })
}

resource "aws_iam_role" "synth_202" {
  name = format("vantage-synth-role-%s", "202")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "202")
    idx  = 202
  })
}

resource "aws_subnet" "synth_202" {
  vpc_id     = format("vpc-synth-%s", "202")
  cidr_block = cidrsubnet("10.2.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "202") })
}

resource "aws_iam_role" "synth_203" {
  name = format("vantage-synth-role-%s", "203")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "203")
    idx  = 203
  })
}

resource "aws_subnet" "synth_203" {
  vpc_id     = format("vpc-synth-%s", "203")
  cidr_block = cidrsubnet("10.3.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "203") })
}

resource "aws_iam_role" "synth_204" {
  name = format("vantage-synth-role-%s", "204")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "204")
    idx  = 204
  })
}

resource "aws_subnet" "synth_204" {
  vpc_id     = format("vpc-synth-%s", "204")
  cidr_block = cidrsubnet("10.4.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "204") })
}

resource "aws_iam_role" "synth_205" {
  name = format("vantage-synth-role-%s", "205")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "205")
    idx  = 205
  })
}

resource "aws_subnet" "synth_205" {
  vpc_id     = format("vpc-synth-%s", "205")
  cidr_block = cidrsubnet("10.5.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "205") })
}

resource "aws_iam_role" "synth_206" {
  name = format("vantage-synth-role-%s", "206")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "206")
    idx  = 206
  })
}

resource "aws_subnet" "synth_206" {
  vpc_id     = format("vpc-synth-%s", "206")
  cidr_block = cidrsubnet("10.6.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "206") })
}

resource "aws_iam_role" "synth_207" {
  name = format("vantage-synth-role-%s", "207")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "207")
    idx  = 207
  })
}

resource "aws_subnet" "synth_207" {
  vpc_id     = format("vpc-synth-%s", "207")
  cidr_block = cidrsubnet("10.7.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "207") })
}

resource "aws_iam_role" "synth_208" {
  name = format("vantage-synth-role-%s", "208")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "208")
    idx  = 208
  })
}

resource "aws_subnet" "synth_208" {
  vpc_id     = format("vpc-synth-%s", "208")
  cidr_block = cidrsubnet("10.8.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "208") })
}

resource "aws_iam_role" "synth_209" {
  name = format("vantage-synth-role-%s", "209")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "209")
    idx  = 209
  })
}

resource "aws_subnet" "synth_209" {
  vpc_id     = format("vpc-synth-%s", "209")
  cidr_block = cidrsubnet("10.9.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "209") })
}

resource "aws_iam_role" "synth_210" {
  name = format("vantage-synth-role-%s", "210")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "210")
    idx  = 210
  })
}

resource "aws_subnet" "synth_210" {
  vpc_id     = format("vpc-synth-%s", "210")
  cidr_block = cidrsubnet("10.10.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "210") })
}

resource "aws_iam_role" "synth_211" {
  name = format("vantage-synth-role-%s", "211")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "211")
    idx  = 211
  })
}

resource "aws_subnet" "synth_211" {
  vpc_id     = format("vpc-synth-%s", "211")
  cidr_block = cidrsubnet("10.11.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "211") })
}

resource "aws_iam_role" "synth_212" {
  name = format("vantage-synth-role-%s", "212")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "212")
    idx  = 212
  })
}

resource "aws_subnet" "synth_212" {
  vpc_id     = format("vpc-synth-%s", "212")
  cidr_block = cidrsubnet("10.12.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "212") })
}

resource "aws_iam_role" "synth_213" {
  name = format("vantage-synth-role-%s", "213")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "213")
    idx  = 213
  })
}

resource "aws_subnet" "synth_213" {
  vpc_id     = format("vpc-synth-%s", "213")
  cidr_block = cidrsubnet("10.13.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "213") })
}

resource "aws_iam_role" "synth_214" {
  name = format("vantage-synth-role-%s", "214")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "214")
    idx  = 214
  })
}

resource "aws_subnet" "synth_214" {
  vpc_id     = format("vpc-synth-%s", "214")
  cidr_block = cidrsubnet("10.14.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "214") })
}

resource "aws_iam_role" "synth_215" {
  name = format("vantage-synth-role-%s", "215")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "215")
    idx  = 215
  })
}

resource "aws_subnet" "synth_215" {
  vpc_id     = format("vpc-synth-%s", "215")
  cidr_block = cidrsubnet("10.15.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "215") })
}

resource "aws_iam_role" "synth_216" {
  name = format("vantage-synth-role-%s", "216")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "216")
    idx  = 216
  })
}

resource "aws_subnet" "synth_216" {
  vpc_id     = format("vpc-synth-%s", "216")
  cidr_block = cidrsubnet("10.16.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "216") })
}

resource "aws_iam_role" "synth_217" {
  name = format("vantage-synth-role-%s", "217")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "217")
    idx  = 217
  })
}

resource "aws_subnet" "synth_217" {
  vpc_id     = format("vpc-synth-%s", "217")
  cidr_block = cidrsubnet("10.17.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "217") })
}

resource "aws_iam_role" "synth_218" {
  name = format("vantage-synth-role-%s", "218")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "218")
    idx  = 218
  })
}

resource "aws_subnet" "synth_218" {
  vpc_id     = format("vpc-synth-%s", "218")
  cidr_block = cidrsubnet("10.18.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "218") })
}

resource "aws_iam_role" "synth_219" {
  name = format("vantage-synth-role-%s", "219")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "219")
    idx  = 219
  })
}

resource "aws_subnet" "synth_219" {
  vpc_id     = format("vpc-synth-%s", "219")
  cidr_block = cidrsubnet("10.19.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "219") })
}

resource "aws_iam_role" "synth_220" {
  name = format("vantage-synth-role-%s", "220")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "220")
    idx  = 220
  })
}

resource "aws_subnet" "synth_220" {
  vpc_id     = format("vpc-synth-%s", "220")
  cidr_block = cidrsubnet("10.20.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "220") })
}

resource "aws_iam_role" "synth_221" {
  name = format("vantage-synth-role-%s", "221")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "221")
    idx  = 221
  })
}

resource "aws_subnet" "synth_221" {
  vpc_id     = format("vpc-synth-%s", "221")
  cidr_block = cidrsubnet("10.21.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "221") })
}

resource "aws_iam_role" "synth_222" {
  name = format("vantage-synth-role-%s", "222")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "222")
    idx  = 222
  })
}

resource "aws_subnet" "synth_222" {
  vpc_id     = format("vpc-synth-%s", "222")
  cidr_block = cidrsubnet("10.22.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "222") })
}

resource "aws_iam_role" "synth_223" {
  name = format("vantage-synth-role-%s", "223")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "223")
    idx  = 223
  })
}

resource "aws_subnet" "synth_223" {
  vpc_id     = format("vpc-synth-%s", "223")
  cidr_block = cidrsubnet("10.23.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "223") })
}

resource "aws_iam_role" "synth_224" {
  name = format("vantage-synth-role-%s", "224")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "224")
    idx  = 224
  })
}

resource "aws_subnet" "synth_224" {
  vpc_id     = format("vpc-synth-%s", "224")
  cidr_block = cidrsubnet("10.24.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "224") })
}

resource "aws_iam_role" "synth_225" {
  name = format("vantage-synth-role-%s", "225")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "225")
    idx  = 225
  })
}

resource "aws_subnet" "synth_225" {
  vpc_id     = format("vpc-synth-%s", "225")
  cidr_block = cidrsubnet("10.25.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "225") })
}

resource "aws_iam_role" "synth_226" {
  name = format("vantage-synth-role-%s", "226")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "226")
    idx  = 226
  })
}

resource "aws_subnet" "synth_226" {
  vpc_id     = format("vpc-synth-%s", "226")
  cidr_block = cidrsubnet("10.26.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "226") })
}

resource "aws_iam_role" "synth_227" {
  name = format("vantage-synth-role-%s", "227")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "227")
    idx  = 227
  })
}

resource "aws_subnet" "synth_227" {
  vpc_id     = format("vpc-synth-%s", "227")
  cidr_block = cidrsubnet("10.27.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "227") })
}

resource "aws_iam_role" "synth_228" {
  name = format("vantage-synth-role-%s", "228")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "228")
    idx  = 228
  })
}

resource "aws_subnet" "synth_228" {
  vpc_id     = format("vpc-synth-%s", "228")
  cidr_block = cidrsubnet("10.28.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "228") })
}

resource "aws_iam_role" "synth_229" {
  name = format("vantage-synth-role-%s", "229")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "229")
    idx  = 229
  })
}

resource "aws_subnet" "synth_229" {
  vpc_id     = format("vpc-synth-%s", "229")
  cidr_block = cidrsubnet("10.29.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "229") })
}

resource "aws_iam_role" "synth_230" {
  name = format("vantage-synth-role-%s", "230")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "230")
    idx  = 230
  })
}

resource "aws_subnet" "synth_230" {
  vpc_id     = format("vpc-synth-%s", "230")
  cidr_block = cidrsubnet("10.30.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "230") })
}

resource "aws_iam_role" "synth_231" {
  name = format("vantage-synth-role-%s", "231")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "231")
    idx  = 231
  })
}

resource "aws_subnet" "synth_231" {
  vpc_id     = format("vpc-synth-%s", "231")
  cidr_block = cidrsubnet("10.31.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "231") })
}

resource "aws_iam_role" "synth_232" {
  name = format("vantage-synth-role-%s", "232")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "232")
    idx  = 232
  })
}

resource "aws_subnet" "synth_232" {
  vpc_id     = format("vpc-synth-%s", "232")
  cidr_block = cidrsubnet("10.32.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "232") })
}

resource "aws_iam_role" "synth_233" {
  name = format("vantage-synth-role-%s", "233")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "233")
    idx  = 233
  })
}

resource "aws_subnet" "synth_233" {
  vpc_id     = format("vpc-synth-%s", "233")
  cidr_block = cidrsubnet("10.33.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "233") })
}

resource "aws_iam_role" "synth_234" {
  name = format("vantage-synth-role-%s", "234")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "234")
    idx  = 234
  })
}

resource "aws_subnet" "synth_234" {
  vpc_id     = format("vpc-synth-%s", "234")
  cidr_block = cidrsubnet("10.34.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "234") })
}

resource "aws_iam_role" "synth_235" {
  name = format("vantage-synth-role-%s", "235")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "235")
    idx  = 235
  })
}

resource "aws_subnet" "synth_235" {
  vpc_id     = format("vpc-synth-%s", "235")
  cidr_block = cidrsubnet("10.35.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "235") })
}

resource "aws_iam_role" "synth_236" {
  name = format("vantage-synth-role-%s", "236")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "236")
    idx  = 236
  })
}

resource "aws_subnet" "synth_236" {
  vpc_id     = format("vpc-synth-%s", "236")
  cidr_block = cidrsubnet("10.36.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "236") })
}

resource "aws_iam_role" "synth_237" {
  name = format("vantage-synth-role-%s", "237")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "237")
    idx  = 237
  })
}

resource "aws_subnet" "synth_237" {
  vpc_id     = format("vpc-synth-%s", "237")
  cidr_block = cidrsubnet("10.37.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "237") })
}

resource "aws_iam_role" "synth_238" {
  name = format("vantage-synth-role-%s", "238")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "238")
    idx  = 238
  })
}

resource "aws_subnet" "synth_238" {
  vpc_id     = format("vpc-synth-%s", "238")
  cidr_block = cidrsubnet("10.38.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "238") })
}

resource "aws_iam_role" "synth_239" {
  name = format("vantage-synth-role-%s", "239")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "239")
    idx  = 239
  })
}

resource "aws_subnet" "synth_239" {
  vpc_id     = format("vpc-synth-%s", "239")
  cidr_block = cidrsubnet("10.39.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "239") })
}

resource "aws_iam_role" "synth_240" {
  name = format("vantage-synth-role-%s", "240")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "240")
    idx  = 240
  })
}

resource "aws_subnet" "synth_240" {
  vpc_id     = format("vpc-synth-%s", "240")
  cidr_block = cidrsubnet("10.40.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "240") })
}

resource "aws_iam_role" "synth_241" {
  name = format("vantage-synth-role-%s", "241")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "241")
    idx  = 241
  })
}

resource "aws_subnet" "synth_241" {
  vpc_id     = format("vpc-synth-%s", "241")
  cidr_block = cidrsubnet("10.41.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "241") })
}

resource "aws_iam_role" "synth_242" {
  name = format("vantage-synth-role-%s", "242")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "242")
    idx  = 242
  })
}

resource "aws_subnet" "synth_242" {
  vpc_id     = format("vpc-synth-%s", "242")
  cidr_block = cidrsubnet("10.42.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "242") })
}

resource "aws_iam_role" "synth_243" {
  name = format("vantage-synth-role-%s", "243")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "243")
    idx  = 243
  })
}

resource "aws_subnet" "synth_243" {
  vpc_id     = format("vpc-synth-%s", "243")
  cidr_block = cidrsubnet("10.43.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "243") })
}

resource "aws_iam_role" "synth_244" {
  name = format("vantage-synth-role-%s", "244")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "244")
    idx  = 244
  })
}

resource "aws_subnet" "synth_244" {
  vpc_id     = format("vpc-synth-%s", "244")
  cidr_block = cidrsubnet("10.44.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "244") })
}

resource "aws_iam_role" "synth_245" {
  name = format("vantage-synth-role-%s", "245")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "245")
    idx  = 245
  })
}

resource "aws_subnet" "synth_245" {
  vpc_id     = format("vpc-synth-%s", "245")
  cidr_block = cidrsubnet("10.45.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "245") })
}

resource "aws_iam_role" "synth_246" {
  name = format("vantage-synth-role-%s", "246")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "246")
    idx  = 246
  })
}

resource "aws_subnet" "synth_246" {
  vpc_id     = format("vpc-synth-%s", "246")
  cidr_block = cidrsubnet("10.46.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "246") })
}

resource "aws_iam_role" "synth_247" {
  name = format("vantage-synth-role-%s", "247")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "247")
    idx  = 247
  })
}

resource "aws_subnet" "synth_247" {
  vpc_id     = format("vpc-synth-%s", "247")
  cidr_block = cidrsubnet("10.47.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "247") })
}

resource "aws_iam_role" "synth_248" {
  name = format("vantage-synth-role-%s", "248")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "248")
    idx  = 248
  })
}

resource "aws_subnet" "synth_248" {
  vpc_id     = format("vpc-synth-%s", "248")
  cidr_block = cidrsubnet("10.48.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "248") })
}

resource "aws_iam_role" "synth_249" {
  name = format("vantage-synth-role-%s", "249")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "249")
    idx  = 249
  })
}

resource "aws_subnet" "synth_249" {
  vpc_id     = format("vpc-synth-%s", "249")
  cidr_block = cidrsubnet("10.49.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "249") })
}

resource "aws_iam_role" "synth_250" {
  name = format("vantage-synth-role-%s", "250")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "250")
    idx  = 250
  })
}

resource "aws_subnet" "synth_250" {
  vpc_id     = format("vpc-synth-%s", "250")
  cidr_block = cidrsubnet("10.50.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "250") })
}

resource "aws_iam_role" "synth_251" {
  name = format("vantage-synth-role-%s", "251")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "251")
    idx  = 251
  })
}

resource "aws_subnet" "synth_251" {
  vpc_id     = format("vpc-synth-%s", "251")
  cidr_block = cidrsubnet("10.51.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "251") })
}

resource "aws_iam_role" "synth_252" {
  name = format("vantage-synth-role-%s", "252")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "252")
    idx  = 252
  })
}

resource "aws_subnet" "synth_252" {
  vpc_id     = format("vpc-synth-%s", "252")
  cidr_block = cidrsubnet("10.52.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "252") })
}

resource "aws_iam_role" "synth_253" {
  name = format("vantage-synth-role-%s", "253")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "253")
    idx  = 253
  })
}

resource "aws_subnet" "synth_253" {
  vpc_id     = format("vpc-synth-%s", "253")
  cidr_block = cidrsubnet("10.53.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "253") })
}

resource "aws_iam_role" "synth_254" {
  name = format("vantage-synth-role-%s", "254")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "254")
    idx  = 254
  })
}

resource "aws_subnet" "synth_254" {
  vpc_id     = format("vpc-synth-%s", "254")
  cidr_block = cidrsubnet("10.54.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "254") })
}

resource "aws_iam_role" "synth_255" {
  name = format("vantage-synth-role-%s", "255")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "255")
    idx  = 255
  })
}

resource "aws_subnet" "synth_255" {
  vpc_id     = format("vpc-synth-%s", "255")
  cidr_block = cidrsubnet("10.55.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "255") })
}

resource "aws_iam_role" "synth_256" {
  name = format("vantage-synth-role-%s", "256")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "256")
    idx  = 256
  })
}

resource "aws_subnet" "synth_256" {
  vpc_id     = format("vpc-synth-%s", "256")
  cidr_block = cidrsubnet("10.56.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "256") })
}

resource "aws_iam_role" "synth_257" {
  name = format("vantage-synth-role-%s", "257")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "257")
    idx  = 257
  })
}

resource "aws_subnet" "synth_257" {
  vpc_id     = format("vpc-synth-%s", "257")
  cidr_block = cidrsubnet("10.57.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "257") })
}

resource "aws_iam_role" "synth_258" {
  name = format("vantage-synth-role-%s", "258")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "258")
    idx  = 258
  })
}

resource "aws_subnet" "synth_258" {
  vpc_id     = format("vpc-synth-%s", "258")
  cidr_block = cidrsubnet("10.58.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "258") })
}

resource "aws_iam_role" "synth_259" {
  name = format("vantage-synth-role-%s", "259")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "259")
    idx  = 259
  })
}

resource "aws_subnet" "synth_259" {
  vpc_id     = format("vpc-synth-%s", "259")
  cidr_block = cidrsubnet("10.59.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "259") })
}

resource "aws_iam_role" "synth_260" {
  name = format("vantage-synth-role-%s", "260")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "260")
    idx  = 260
  })
}

resource "aws_subnet" "synth_260" {
  vpc_id     = format("vpc-synth-%s", "260")
  cidr_block = cidrsubnet("10.60.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "260") })
}

resource "aws_iam_role" "synth_261" {
  name = format("vantage-synth-role-%s", "261")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "261")
    idx  = 261
  })
}

resource "aws_subnet" "synth_261" {
  vpc_id     = format("vpc-synth-%s", "261")
  cidr_block = cidrsubnet("10.61.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "261") })
}

resource "aws_iam_role" "synth_262" {
  name = format("vantage-synth-role-%s", "262")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "262")
    idx  = 262
  })
}

resource "aws_subnet" "synth_262" {
  vpc_id     = format("vpc-synth-%s", "262")
  cidr_block = cidrsubnet("10.62.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "262") })
}

resource "aws_iam_role" "synth_263" {
  name = format("vantage-synth-role-%s", "263")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "263")
    idx  = 263
  })
}

resource "aws_subnet" "synth_263" {
  vpc_id     = format("vpc-synth-%s", "263")
  cidr_block = cidrsubnet("10.63.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "263") })
}

resource "aws_iam_role" "synth_264" {
  name = format("vantage-synth-role-%s", "264")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "264")
    idx  = 264
  })
}

resource "aws_subnet" "synth_264" {
  vpc_id     = format("vpc-synth-%s", "264")
  cidr_block = cidrsubnet("10.64.0.0/16", 8, 8)
  tags       = merge(local.common, { Name = format("subnet-%s", "264") })
}

resource "aws_iam_role" "synth_265" {
  name = format("vantage-synth-role-%s", "265")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "265")
    idx  = 265
  })
}

resource "aws_subnet" "synth_265" {
  vpc_id     = format("vpc-synth-%s", "265")
  cidr_block = cidrsubnet("10.65.0.0/16", 8, 9)
  tags       = merge(local.common, { Name = format("subnet-%s", "265") })
}

resource "aws_iam_role" "synth_266" {
  name = format("vantage-synth-role-%s", "266")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "266")
    idx  = 266
  })
}

resource "aws_subnet" "synth_266" {
  vpc_id     = format("vpc-synth-%s", "266")
  cidr_block = cidrsubnet("10.66.0.0/16", 8, 10)
  tags       = merge(local.common, { Name = format("subnet-%s", "266") })
}

resource "aws_iam_role" "synth_267" {
  name = format("vantage-synth-role-%s", "267")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "267")
    idx  = 267
  })
}

resource "aws_subnet" "synth_267" {
  vpc_id     = format("vpc-synth-%s", "267")
  cidr_block = cidrsubnet("10.67.0.0/16", 8, 11)
  tags       = merge(local.common, { Name = format("subnet-%s", "267") })
}

resource "aws_iam_role" "synth_268" {
  name = format("vantage-synth-role-%s", "268")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "268")
    idx  = 268
  })
}

resource "aws_subnet" "synth_268" {
  vpc_id     = format("vpc-synth-%s", "268")
  cidr_block = cidrsubnet("10.68.0.0/16", 8, 12)
  tags       = merge(local.common, { Name = format("subnet-%s", "268") })
}

resource "aws_iam_role" "synth_269" {
  name = format("vantage-synth-role-%s", "269")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "269")
    idx  = 269
  })
}

resource "aws_subnet" "synth_269" {
  vpc_id     = format("vpc-synth-%s", "269")
  cidr_block = cidrsubnet("10.69.0.0/16", 8, 13)
  tags       = merge(local.common, { Name = format("subnet-%s", "269") })
}

resource "aws_iam_role" "synth_270" {
  name = format("vantage-synth-role-%s", "270")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "270")
    idx  = 270
  })
}

resource "aws_subnet" "synth_270" {
  vpc_id     = format("vpc-synth-%s", "270")
  cidr_block = cidrsubnet("10.70.0.0/16", 8, 14)
  tags       = merge(local.common, { Name = format("subnet-%s", "270") })
}

resource "aws_iam_role" "synth_271" {
  name = format("vantage-synth-role-%s", "271")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "271")
    idx  = 271
  })
}

resource "aws_subnet" "synth_271" {
  vpc_id     = format("vpc-synth-%s", "271")
  cidr_block = cidrsubnet("10.71.0.0/16", 8, 15)
  tags       = merge(local.common, { Name = format("subnet-%s", "271") })
}

resource "aws_iam_role" "synth_272" {
  name = format("vantage-synth-role-%s", "272")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "272")
    idx  = 272
  })
}

resource "aws_subnet" "synth_272" {
  vpc_id     = format("vpc-synth-%s", "272")
  cidr_block = cidrsubnet("10.72.0.0/16", 8, 0)
  tags       = merge(local.common, { Name = format("subnet-%s", "272") })
}

resource "aws_iam_role" "synth_273" {
  name = format("vantage-synth-role-%s", "273")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "273")
    idx  = 273
  })
}

resource "aws_subnet" "synth_273" {
  vpc_id     = format("vpc-synth-%s", "273")
  cidr_block = cidrsubnet("10.73.0.0/16", 8, 1)
  tags       = merge(local.common, { Name = format("subnet-%s", "273") })
}

resource "aws_iam_role" "synth_274" {
  name = format("vantage-synth-role-%s", "274")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "274")
    idx  = 274
  })
}

resource "aws_subnet" "synth_274" {
  vpc_id     = format("vpc-synth-%s", "274")
  cidr_block = cidrsubnet("10.74.0.0/16", 8, 2)
  tags       = merge(local.common, { Name = format("subnet-%s", "274") })
}

resource "aws_iam_role" "synth_275" {
  name = format("vantage-synth-role-%s", "275")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "275")
    idx  = 275
  })
}

resource "aws_subnet" "synth_275" {
  vpc_id     = format("vpc-synth-%s", "275")
  cidr_block = cidrsubnet("10.75.0.0/16", 8, 3)
  tags       = merge(local.common, { Name = format("subnet-%s", "275") })
}

resource "aws_iam_role" "synth_276" {
  name = format("vantage-synth-role-%s", "276")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "276")
    idx  = 276
  })
}

resource "aws_subnet" "synth_276" {
  vpc_id     = format("vpc-synth-%s", "276")
  cidr_block = cidrsubnet("10.76.0.0/16", 8, 4)
  tags       = merge(local.common, { Name = format("subnet-%s", "276") })
}

resource "aws_iam_role" "synth_277" {
  name = format("vantage-synth-role-%s", "277")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "277")
    idx  = 277
  })
}

resource "aws_subnet" "synth_277" {
  vpc_id     = format("vpc-synth-%s", "277")
  cidr_block = cidrsubnet("10.77.0.0/16", 8, 5)
  tags       = merge(local.common, { Name = format("subnet-%s", "277") })
}

resource "aws_iam_role" "synth_278" {
  name = format("vantage-synth-role-%s", "278")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "278")
    idx  = 278
  })
}

resource "aws_subnet" "synth_278" {
  vpc_id     = format("vpc-synth-%s", "278")
  cidr_block = cidrsubnet("10.78.0.0/16", 8, 6)
  tags       = merge(local.common, { Name = format("subnet-%s", "278") })
}

resource "aws_iam_role" "synth_279" {
  name = format("vantage-synth-role-%s", "279")
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(local.common, {
    Name = format("role-%s", "279")
    idx  = 279
  })
}

resource "aws_subnet" "synth_279" {
  vpc_id     = format("vpc-synth-%s", "279")
  cidr_block = cidrsubnet("10.79.0.0/16", 8, 7)
  tags       = merge(local.common, { Name = format("subnet-%s", "279") })
}

