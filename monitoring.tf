# =============================================================================
# MONITORING — Website-down alerts (2 systems)
# =============================================================================

resource "aws_sns_topic" "website_alerts" {
  name = "nas-financial-website-alerts"
}

resource "aws_sns_topic_subscription" "website_alerts_email" {
  count     = length(var.alert_email) > 0 ? 1 : 0
  topic_arn = aws_sns_topic.website_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "nas-financial-alb-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Website ALB returning 5xx errors"
  alarm_actions       = [aws_sns_topic.website_alerts.arn]
  dimensions = { LoadBalancer = aws_lb.alb.arn_suffix }
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_hosts" {
  alarm_name          = "nas-financial-unhealthy-hosts"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "Website has unhealthy target(s)"
  alarm_actions       = [aws_sns_topic.website_alerts.arn]
  dimensions = {
    LoadBalancer = aws_lb.alb.arn_suffix
    TargetGroup  = aws_lb_target_group.tg.arn_suffix
  }
}
