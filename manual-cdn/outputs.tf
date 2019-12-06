output "distribution_id" {
  value = aws_cloudfront_distribution.cdn_distribution.id
}

output "domain_name" {
  value = aws_cloudfront_distribution.cdn_distribution.domain_name
}
