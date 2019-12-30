provider "aws" {
  region = "us-gov-west-1"
}

variable "private_key_pem" {
  type = string
}

variable "cert_pem" {
  type = string
}

variable "chain_pem" {
  type = string
}

variable "custom_domain" {
  type = string
}

variable "listener_arn" {
  type = string
}

resource "aws_iam_server_certificate" "iam_cert" {
  private_key      = file(var.private_key_pem)
  certificate_body = file(var.cert_pem)
  certificate_chain = file(var.chain_pem)
  name = var.custom_domain
}

resource "aws_lb_listener_certificate" "listener_cert" {
  listener_arn    = var.listener_arn
  certificate_arn = aws_iam_server_certificate.iam_cert.arn
}