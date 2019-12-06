provider "aws" {
  region = "us-east-1"
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

variable "origin_id" {
  type = string
}

variable "origin_domain" {
  type = string
}

variable "origin_path" {
  type = string
  default = ""
}

resource "aws_acm_certificate" "cdn_cert" {
  private_key      = file(var.private_key_pem)
  certificate_body = file(var.cert_pem)
  certificate_chain = file(var.chain_pem)
  tags = {
    Name = var.custom_domain
  }
}

resource "aws_cloudfront_distribution" "cdn_distribution" {
  
  aliases = [var.custom_domain]

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
  
    forwarded_values {
      query_string = true
      cookies {
        forward = "all"
      }
    }
    
    target_origin_id = var.origin_id
    viewer_protocol_policy = "redirect-to-https"
  }

  enabled             = true
  is_ipv6_enabled     = true

  origin {
    domain_name = var.origin_domain
    origin_id   = var.origin_id
    origin_path = var.origin_path

    custom_origin_config {
      http_port = 80
      https_port = 443
      origin_protocol_policy = "https-only" 
      origin_ssl_protocols = ["TLSv1.2"]
    }
  }
  price_class = "PriceClass_100"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn = aws_acm_certificate.cdn_cert.arn
    minimum_protocol_version = "TLSv1.2_2018"
    ssl_support_method = "sni-only"
  }
}