import boto3
import pytest
from botocore.exceptions import ClientError

def test_dynamodb_table_exists():
    """Test that the DCTechEventsSubmissions table exists and has correct configuration."""
    dynamodb = boto3.client('dynamodb')
    
    try:
        # Get table description
        response = dynamodb.describe_table(TableName='DCTechEventsSubmissions')
        table = response['Table']
        
        # Check table name
        assert table['TableName'] == 'DCTechEventsSubmissions'
        
        # Check key schema
        key_schema = table['KeySchema']
        assert len(key_schema) == 1
        assert key_schema[0]['AttributeName'] == 'submission_id'
        assert key_schema[0]['KeyType'] == 'HASH'
        
        # Check attribute definitions
        attrs = table['AttributeDefinitions']
        assert len(attrs) == 1
        assert attrs[0]['AttributeName'] == 'submission_id'
        assert attrs[0]['AttributeType'] == 'S'
        
        # Check billing mode
        assert table['BillingModeSummary']['BillingMode'] == 'PAY_PER_REQUEST'
        
        # Check table status
        assert table['TableStatus'] == 'ACTIVE'
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            pytest.fail("Table DCTechEventsSubmissions does not exist")
        raise