# SYNTHETIC — for-expressions. Not copied from any hold-out.

variable "subnet_ids" {
  type    = list(string)
  default = ["subnet-aaa", "subnet-bbb"]
}

variable "cidrs" {
  type    = list(string)
  default = ["10.1.0.0/24", "10.1.1.0/24"]
}

locals {
  named = { for idx, cidr in var.cidrs : format("net-%s", idx) => cidr }
  ids   = [for s in var.subnet_ids : s]
  filtered = [for s in var.subnet_ids : s if s != ""]
  pairs = { for k, v in local.named : k => format("%s/%s", k, v) }
}

resource "aws_security_group" "synth" {
  name   = "vantage-synth-sg"
  vpc_id = "vpc-synth"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [for c in var.cidrs : c]
  }
}

resource "aws_lb" "synth" {
  name               = format("vantage-synth-lb")
  load_balancer_type = "application"
  subnets            = [for s in var.subnet_ids : s]
  tags               = { for k, v in local.named : k => v }
}

resource "aws_s3_bucket" "for_expr" {
  bucket = "vantage-synth-for-expr"
  acl    = "private"
}
