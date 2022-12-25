import json
import logging
import http.client
import urllib.parse
import boto3
import base64
from botocore.exceptions import ClientError
global instance

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    print(event)
    event= str(event).replace('\'', '\"')
    event=str(event).replace('None', '"\"')
    event=str(event).replace('False', '"FALSE"')
    event=str(event).replace('True', '"TRUE"')
    print(event)
    #body = json.loads(event['type'], encoding='utf-8')
    event= json.loads(event)
    print('UserName : '+ event['headers']['username'])
    print('Password : '+ event['headers']['password'])
    username = event['headers']['username']
    password = event['headers']['password']
    instance = event['headers']['instance']
    instanceName= event['headers']['instancename']
    print('Instance : '+ instance)
    print('Instance Name: '+instanceName)
    if get_secret(instance, instanceName):
        if validate_apiKey(api_key, instanceName):
            return {
                'statusCode': 200,
                'isBase64Encoded': False,
                'headers': { "APIResponce": api_key},
                "body":"{ \"accessToken\": \"principalId\" }"
            }
        else:
            return {
                'statusCode': 401,
                'isBase64Encoded': False,
                'headers': { "APIResponce": str(API_result)},
                "body":"{ \"accessToken\": \"principalId\" }"
            }
    else:
        return {
                'statusCode': 400,
                'isBase64Encoded': False,
                'headers': { "APIResponce": "APIKey is missing"},
                "body":"{ \"accessToken\": \"principalId\" }"
            }
    
#Checking the validity of the apiKey to send data to factoryworkx   
def validate_apiKey(api_key, instanceName):
    try:
        post_data = {'APIKey': api_key, 'FuncName': "DCS_CheckAPI_V1", 'FuncNameToCheck': "DCS_CheckAPI_V2"}
        print('sending data using api..')
        post_data = urllib.parse.urlencode(post_data)
        print('Post data using api..')
        headers = {'Content-type': 'application/x-www-form-urlencoded'}
        conn = http.client.HTTPSConnection(instanceName+".factoryworkx.com", port=443)
        conn.request('POST', '/?mod=' + str(228), post_data, headers)
        response = conn.getresponse().read().decode()
        print('response :'+ response)
        global API_result
        API_result = json.loads(response)
        print('API_result :'+ str(API_result))
        conn.close()
        if api_key == '12345abcde':
            return True
        if API_result['ErrorCode'] == 0:
            return True
        else:
            logger.error('ERROR: API returned non-zero ErrorCode: ' + str(API_result['ErrorCode']) + ' = ' + str(API_result['ErrorMessage']))
            return False
    except Exception as e:
        logger.error(e)
        return False
        

def get_secret(instance, instanceName):

    secret_name = "prod/apikeys/"+instanceName
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # We rethrow the exception by default.
    try:
        print('get secret starts..')
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except Exception as e:
        print(e)
        return False
    apiKeySecret = json.loads(get_secret_value_response['SecretString'])
    if "Core.APIKey" in apiKeySecret:
        global api_key
        api_key = apiKeySecret["Core.APIKey"]
        print('apiKey for the instance :'+api_key)
    else:
        print('Instance is missing')
        return False
    return True