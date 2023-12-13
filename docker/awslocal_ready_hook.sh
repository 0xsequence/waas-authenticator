#!/bin/bash

shopt -s expand_aliases

if [ ! "$(type -t awslocal)" = "alias" ] && [ ! -x "$(command -v awslocal)" ]; then
    alias awslocal="AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=${DEFAULT_REGION:-$AWS_DEFAULT_REGION} aws --endpoint-url=http://${LOCALSTACK_HOST:-localhost}:4566"
fi

awslocal kms create-key --region us-east-1 --tags '[{"TagKey":"_custom_id_","TagValue":"aeb99e0f-9e89-44de-a084-e1817af47778"}]'
awslocal kms create-key --region us-east-1 --tags '[{"TagKey":"_custom_id_","TagValue":"27ebbde0-49d2-4cb6-ad78-4f2c24fe7b79"}]'

awslocal dynamodb create-table \
  --region us-east-1 \
  --table-name TenantsTable \
  --attribute-definitions AttributeName=ProjectID,AttributeType=N AttributeName=Version,AttributeType=N \
  --key-schema AttributeName=ProjectID,KeyType=HASH AttributeName=Version,KeyType=SORT \
  --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=10

awslocal dynamodb create-table \
  --region us-east-1 \
  --table-name SessionsTable \
  --attribute-definitions AttributeName=ProjectID,AttributeType=N AttributeName=ID,AttributeType=S AttributeName=UserID,AttributeType=S AttributeName=CreatedAt,AttributeType=S \
  --key-schema AttributeName=ProjectID,KeyType=HASH AttributeName=ID,KeyType=SORT \
  --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=10 \
  --global-secondary-indexes "IndexName=UserID-Index,KeySchema=[{AttributeName=UserID,KeyType=HASH},{AttributeName=CreatedAt,KeyType=SORT}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=10,WriteCapacityUnits=10}"

