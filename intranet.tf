# =============================================================================
# INTRANET — Internal ALB + ASG (VPC-only, HTTP)
# =============================================================================

resource "aws_lb_target_group" "intranet_tg" {
  name        = "nas-intranet-tg"
  target_type = "instance"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
}

resource "aws_lb" "intranet_alb" {
  name               = "nas-intranet-alb"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.intranet_alb_sg.id]
  subnets            = [aws_subnet.private1.id, aws_subnet.private2.id]
}

resource "aws_lb_listener" "intranet_http" {
  load_balancer_arn = aws_lb.intranet_alb.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.intranet_tg.arn
  }
}

resource "aws_launch_template" "intranet" {
  name_prefix   = "nas-intranet-lt-"
  image_id      = data.aws_ami.amazon_linux_latest.id
  instance_type = var.instance_type
  vpc_security_group_ids = [aws_security_group.intranet_ec2_sg.id]
  tag_specifications {
    resource_type = "instance"
    tags = { Name = "NAS-Intranet-App" }
  }
}

resource "aws_autoscaling_group" "intranet" {
  name                = "nas-intranet-asg"
  min_size            = 1
  max_size            = 2
  desired_capacity    = 1
  target_group_arns   = [aws_lb_target_group.intranet_tg.arn]
  vpc_zone_identifier = [aws_subnet.private1.id, aws_subnet.private2.id]
  launch_template {
    id      = aws_launch_template.intranet.id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = "Intranet-App"
    propagate_at_launch = true
  }
}
