# =============================================================================
# COMPUTE — Public web tier (ASG + Launch Template)
# =============================================================================

resource "aws_launch_template" "ec2_launchtemplate" {
  name_prefix   = "ec2-launchtemplate"
  image_id      = data.aws_ami.amazon_linux_latest.id
  instance_type = var.instance_type
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  iam_instance_profile { name = aws_iam_instance_profile.ec2_ssm.name }
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name      = "ASG-Web-Server"
      ManagedBy = "CloudSpace"
    }
  }
}

resource "aws_autoscaling_group" "asg" {
  name                = "asg-terraform"
  min_size            = 1
  max_size            = 2
  desired_capacity    = 1
  target_group_arns   = [aws_lb_target_group.tg.arn]
  vpc_zone_identifier = [aws_subnet.private1.id, aws_subnet.private2.id]
  launch_template {
    id      = aws_launch_template.ec2_launchtemplate.id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = "ASG-Instances"
    propagate_at_launch = true
  }
}
