#!/bin/bash

shopt -s expand_aliases

if [ ! "$(type -t awslocal)" = "alias" ] && [ ! -x "$(command -v awslocal)" ]; then
    alias awslocal="AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=${DEFAULT_REGION:-$AWS_DEFAULT_REGION} aws --endpoint-url=${LOCALSTACK_ENDPOINT:-http://${LOCALSTACK_HOST:-localhost}:4566}"
fi

awslocal kms create-key --region us-east-1 --tags '[{"TagKey":"_custom_id_","TagValue":"aeb99e0f-9e89-44de-a084-e1817af47778"}]'
awslocal kms create-key --region us-east-1 --tags '[{"TagKey":"_custom_id_","TagValue":"27ebbde0-49d2-4cb6-ad78-4f2c24fe7b79"}]'
awslocal kms create-key --region us-east-1 --key-usage SIGN_VERIFY --key-spec RSA_2048 --tags '[{"TagKey":"_custom_id_","TagValue":"5edb0219-8da9-4842-98fb-e83c6316f3bd"}]'

awslocal ses verify-email-identity --email-address noreply@local.auth.sequence.app

awslocal secretsmanager create-secret \
  --region us-east-1 \
  --name BuilderJWT \
  --secret-string 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXJ2aWNlIjoiV2FhUyJ9.-FAkEOb0jtHhoHv6r4O7U8PGOw_b60M9MnSYN9Bm_7A'

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

awslocal dynamodb create-table \
  --region us-east-1 \
  --table-name AccountsTable \
  --attribute-definitions AttributeName=ProjectID,AttributeType=N AttributeName=Identity,AttributeType=S AttributeName=UserID,AttributeType=S AttributeName=ProjectScopedEmail,AttributeType=S \
  --key-schema AttributeName=ProjectID,KeyType=HASH AttributeName=Identity,KeyType=SORT \
  --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=10 \
  --global-secondary-indexes \
    "IndexName=UserID-Index,KeySchema=[{AttributeName=UserID,KeyType=HASH},{AttributeName=Identity,KeyType=SORT}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=10,WriteCapacityUnits=10}" \
    "IndexName=Email-Index,KeySchema=[{AttributeName=ProjectScopedEmail,KeyType=HASH},{AttributeName=Identity,KeyType=SORT}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=10,WriteCapacityUnits=10}"

awslocal dynamodb create-table \
  --region us-east-1 \
  --table-name VerificationContextsTable \
  --attribute-definitions AttributeName=ID,AttributeType=S \
  --key-schema AttributeName=ID,KeyType=HASH \
  --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=10

echo "Finished bootstrapping localstack resources!"
