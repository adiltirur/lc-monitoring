const { CloudFrontClient } = require('@aws-sdk/client-cloudfront');
const { CloudWatchClient } = require('@aws-sdk/client-cloudwatch');
const { CloudWatchLogsClient } = require('@aws-sdk/client-cloudwatch-logs');
const { EC2Client } = require('@aws-sdk/client-ec2');
const { ElastiCacheClient } = require('@aws-sdk/client-elasticache');
const { ElasticLoadBalancingV2Client } = require('@aws-sdk/client-elastic-load-balancing-v2');
const { RDSClient } = require('@aws-sdk/client-rds');
const { S3Client } = require('@aws-sdk/client-s3');

// ─── AWS Monitoring Clients ───────────────────────────────────────────────────
const AWS_REGION = 'eu-central-1';
const ec2Client = new EC2Client({ region: AWS_REGION });
const cloudwatchClient = new CloudWatchClient({ region: AWS_REGION });
const cwLogsClient = new CloudWatchLogsClient({ region: AWS_REGION });
const rdsClient = new RDSClient({ region: AWS_REGION });
const elbv2Client = new ElasticLoadBalancingV2Client({ region: AWS_REGION });
const elasticacheClient = new ElastiCacheClient({ region: AWS_REGION });
const s3Client = new S3Client({ region: AWS_REGION });
const cloudfrontClient = new CloudFrontClient({ region: AWS_REGION });

module.exports = { AWS_REGION, cloudfrontClient, cloudwatchClient, cwLogsClient, ec2Client, elasticacheClient, elbv2Client, rdsClient, s3Client };
