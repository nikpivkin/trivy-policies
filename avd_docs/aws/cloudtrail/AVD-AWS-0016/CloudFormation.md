
Turn on log validation for Cloudtrail

```yaml---
Resources:
  GoodExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true
      EnableLogFileValidation: true
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"

```


