#!/bin/bash

# Exit on any error
set -e

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "Error: AWS CLI is not installed. Please install it first."
    exit 1
fi

# Check if we have AWS credentials configured
if ! aws sts get-caller-identity &> /dev/null; then
    echo "Error: AWS credentials not configured. Please run 'aws configure' first."
    exit 1
fi

echo "Creating DynamoDB table DCTechEventsSubmissions..."

# Create DynamoDB table for event submissions
aws dynamodb create-table \
    --table-name DCTechEventsSubmissions \
    --attribute-definitions \
        AttributeName=submission_id,AttributeType=S \
    --key-schema \
        AttributeName=submission_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --tags Key=Project,Value=DCTechEvents

echo "Waiting for table to be created..."

# Wait for table to be created
aws dynamodb wait table-exists --table-name DCTechEventsSubmissions

echo "Table DCTechEventsSubmissions has been created successfully"