# =============================================================================
# PUBLIC WEBSITE — ALB, Listeners, CloudFront, Route 53
# =============================================================================

resource "aws_lb_target_group" "tg" {
  name        = "tf-lb-tg"
  target_type = "instance"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
}

resource "aws_lb" "alb" {
  name                       = "lb-tf"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb_sg.id]
  subnets                    = [aws_subnet.public1.id, aws_subnet.public2.id]
  enable_deletion_protection  = false
}

resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

resource "aws_lb_listener_rule" "sorry_page" {
  listener_arn = aws_lb_listener.https_listener.arn
  priority     = 100
  action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/html"
      message_body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Access restricted</title></head><body><h1>Sorry you are not in a country authorized to access this web page</h1></body></html>"
      status_code  = "200"
    }
  }
  condition {
    path_pattern {
      values = ["/sorry.html"]
    }
  }
}

resource "aws_cloudfront_distribution" "main" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = ""
  comment             = "NAS Financial - dynamic site (US)"
  price_class         = "PriceClass_100"
  origin {
    domain_name = aws_lb.alb.dns_name
    origin_id   = "alb"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD", "OPTIONS"]
    target_origin_id       = "alb"
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
    forwarded_values {
      query_string = true
      headers      = ["Host"]
      cookies { forward = "all" }
    }
  }
  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US"]
    }
  }
  custom_error_response {
    error_code            = 403
    response_code        = 200
    response_page_path   = "/sorry.html"
    error_caching_min_ttl = 60
  }
  viewer_certificate {
    acm_certificate_arn            = length(var.cloudfront_aliases) > 0 ? var.certificate_arn : null
    ssl_support_method             = length(var.cloudfront_aliases) > 0 ? "sni-only" : null
    minimum_protocol_version       = length(var.cloudfront_aliases) > 0 ? "TLSv1.2_2021" : null
    cloudfront_default_certificate = length(var.cloudfront_aliases) == 0 ? true : null
  }
  aliases = var.cloudfront_aliases
  tags = { Name = "nas-financial-cf-main" }
}

resource "aws_route53_record" "www" {
  zone_id = var.zone_id
  name    = "www.fcjnwudo.com"
  type    = "A"
  alias {
    name                   = aws_cloudfront_distribution.main.domain_name
    zone_id                = aws_cloudfront_distribution.main.hosted_zone_id
    evaluate_target_health = false
  }
}
