# SYNTHETIC — nested ${} interpolations. Not copied from any hold-out.

variable "env" {
  type    = string
  default = "synth"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

locals {
  prefix = "${var.env}-${var.region}"
  nested = "${format("%s-%s", var.env, "${var.region}-core")}"
  triple = "${merge(local.common, { Name = "${format("bucket-%s", var.env)}" })}"
  common = { owner = "vantage-synth" }
}

resource "aws_s3_bucket" "interp" {
  bucket = "${format("%s-%s", var.env, "interp")}"
  acl    = "private"
  tags = {
    Name        = "${local.prefix}-bucket"
    Nested      = "${format("%s/%s", "${var.env}", var.region)}"
    Description = "${file("${path.module}/README.md")}"
  }
}

resource "aws_subnet" "interp" {
  vpc_id     = "${aws_vpc.missing[0].id}"
  cidr_block = "${cidrsubnet(var.vpc_cidr, 4, 2)}"
  tags = {
    Name = "${format("%s-subnet-%s", var.env, "${var.region}")}"
  }
}
