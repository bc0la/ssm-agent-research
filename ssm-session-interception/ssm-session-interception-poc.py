#!/usr/bin/env python3

import requests, json, time, uuid
import websocket
import aws_requests
import aws_msg
import boto3
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def retrieve_meta():
    # Step 1: Obtain the IMDSv2 token
    headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
    resp = requests.put("http://169.254.169.254/latest/api/token", headers=headers)
    if resp.status_code != 200:
        raise Exception(f"Failed to retrieve metadata token: HTTP {resp.status_code}")
    api_token = resp.text
    print(f"Retrieved IMDSv2 token: {api_token}")

    # Step 2: Use the token to get the instance identity document
    headers = {"X-aws-ec2-metadata-token": api_token}
    resp = requests.get("http://169.254.169.254/latest/dynamic/instance-identity/document", headers=headers)
    if resp.status_code != 200:
        raise Exception(f"Failed to retrieve instance identity document: HTTP {resp.status_code}")
    print(f"Retrieved instance identity document: {resp.text}")

    return json.loads(resp.text)



def retrieve_role_name():
    # Obtain the IMDSv2 token
    headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
    resp = requests.put("http://169.254.169.254/latest/api/token", headers=headers)
    if resp.status_code != 200:
        raise Exception(f"Failed to retrieve metadata token: HTTP {resp.status_code}")
    api_token = resp.text
    print(f"Retrieved IMDSv2 token: {api_token}")

    # Use the token to get the IAM role name
    headers = {"X-aws-ec2-metadata-token": api_token}
    resp = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/", headers=headers)
    if resp.status_code != 200:
        raise Exception(f"Failed to retrieve IAM role name: HTTP {resp.status_code}")
    role_name = resp.text.strip()
    if not role_name:
        raise Exception("No IAM role name returned from metadata service.")
    print(f"Retrieved IAM role name: '{role_name}'")
    return role_name




def retrieve_role_creds(role_name):
    # Requesting IMDSv2 token
    headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
    resp = requests.put("http://169.254.169.254/latest/api/token", headers=headers)
    if resp.status_code != 200:
        raise Exception(f"Failed to retrieve metadata token: HTTP {resp.status_code}")
    api_token = resp.text
    print(f"Retrieved IMDSv2 token: {api_token}")

    # Using token to get role credentials
    headers = {"X-aws-ec2-metadata-token": api_token}
    url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
    resp = requests.get(url, headers=headers)
    print(f"Requesting role credentials from: {url}")
    print(f"Response status code: {resp.status_code}")
    print(f"Response text: '{resp.text}'")

    if resp.status_code != 200:
        raise Exception(f"Failed to retrieve role credentials: HTTP {resp.status_code}")
    if not resp.text.strip():
        raise Exception("No role credentials returned from metadata service.")
    return json.loads(resp.text)



def retrieve_role_creds_from_file(file_name):
    with open(file_name, 'r') as r:
        return json.loads("".join(r.readlines()))


def parse_control_channel(data):
    lines = data.split("\n")
    access_token = lines[2][lines[2].find(">")+1:lines[2].find("</")]
    url = lines[3][lines[3].find(">")+1:lines[3].find("</")] 
    return access_token, url


def parse_data_channel(data):
    lines = data.split("\n")
    access_token= lines[2][lines[2].find(">")+1:lines[2].find("</")]
    return access_token


def create_date():
    return int(round(time.time() * 1000))


def fetch_access_token_url(meta, role_creds):
    # Get the control_channel access_token and websocket uri
    resp = aws_requests.post_control_channel(meta['instanceId'], role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])
    access_token, url = parse_control_channel(resp)

    return access_token, url


def build_control_channel(meta, role_creds, access_token, url):
    path = url[url.find("/v1"):]
    control_channel_info = aws_requests.initiate_websocket_connection(url, path, access_token, role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])

    return control_channel_info


def craft_cc_message(access_token):
    return '{"Cookie":null,"MessageSchemaVersion":"1.0","RequestId":"'+str(uuid.uuid4())+'","TokenValue":"'+access_token+'","AgentVersion":"3.0.161.0","PlatformType":"linux"}'


def craft_dc_message(access_token):
    return '{"MessageSchemaVersion":"1.0","RequestId":"'+str(uuid.uuid4())+'","TokenValue":"'+access_token+'","ClientInstanceId":"i-03a6d204ea995a6fa","ClientId":""}'


def build_data_channel(session_id, access_token, role_creds):
    path = "/v1/data-channel/"+session_id+"?role=publish_subscribe"
    data_channel_info = aws_requests.initiate_websocket_connection("wss://ssmmessages.us-east-1.amazonaws.com/v1/data-channel/"+session_id+"?role=publish_subscribe", path, access_token, role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])

    return data_channel_info


def craft_agent_session_state(session_id):
    msg = aws_msg.serialize(
            '{"SchemaVersion":1,"SessionState":"Connected","SessionId":"' + session_id + '"}',  # Message
            "agent_session_state",                                                              # Message Type
            1,                                                                                  # Schema Version
            create_date(),                                                                      # Created Date
            0,                                                                                  # Sequence Number
            3,                                                                                  # Flags
            uuid.uuid4(),                                                                       # Message ID
            0)                                                                                  # Payload Type
    return msg


def craft_acknowledge(session_id, seq_num):
    msg = aws_msg.serialize(
            '{"AcknowledgedMessageType":"input_stream_data","AcknowledgedMessageId":"' + session_id + '","AcknowledgedMessageSequenceNumber":0,"IsSequentialMessage":true}', 
            "acknowledge",                                                                      # Message Type
            1,                                                                                  # Schema Version
            create_date(),                                                                      # Created Date
            seq_num,                                                                            # Sequence Number 
            3,                                                                                  # Flags
            uuid.uuid4(),                                                                       # Message ID
            0)                                                                                  # Payload Type
    return msg


def craft_output_stream_data(message, seq_num):
    msg = aws_msg.serialize(
            message,                                                                            # Message
            "output_stream_data",                                                               # Message Type
            1,                                                                                  # Schema Version
            create_date(),                                                                      # Created Date
            seq_num,                                                                            # Sequence Number
            1,                                                                                  # Flags
            uuid.uuid4(),                                                                       # Message ID
            1)                                                                                  # Payload Type
    return msg

def decrypt_data_key(kms_client, encrypted_data_key_b64):
    encrypted_data_key = base64.b64decode(encrypted_data_key_b64)
    response = kms_client.decrypt(
        CiphertextBlob=encrypted_data_key
    )
    return response['Plaintext']

def encrypt_with_data_key(data_key, plaintext_bytes):
    cipher = AES.new(data_key, AES.MODE_CBC, iv=b'\x00' * 16)
    padded_plaintext = pad(plaintext_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def decrypt_with_data_key(data_key, ciphertext):
    cipher = AES.new(data_key, AES.MODE_CBC, iv=b'\x00' * 16)
    plaintext_padded = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext_padded, AES.block_size)
    return plaintext

def main(kms_key_arn, region):
    # Initialize KMS client
    kms_client = boto3.client('kms', region_name=region)

    # Get role name and credentials
    role_name = retrieve_role_name()
    print("Retrieved role name:", role_name)
    role_creds = retrieve_role_creds(role_name)
    meta = retrieve_meta()

    # Gather info to create the control channel
    access_token, url = fetch_access_token_url(meta, role_creds)
    cc_info = build_control_channel(meta, role_creds, access_token, url)

    # Instantiate the control channel
    control_channel = websocket.WebSocket()
    control_channel.connect(cc_info[0], header=cc_info[1])

    # Get control channel session_id
    control_channel.send(craft_cc_message(access_token))
    first_response = aws_msg.deserialize(control_channel.recv())
    first_response_payload = json.loads(first_response.payload)
    first_response_content = json.loads(first_response_payload['content'])
    session_id = first_response_content['SessionId']
    print("Session ID:", session_id)

    # Gather info to create the data channel
    resp = aws_requests.post_data_channel(session_id, role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])
    access_token = parse_data_channel(resp)

    dc_info = build_data_channel(session_id, access_token, role_creds)

    # Instantiate the data channel
    data_channel = websocket.WebSocket()
    data_channel.connect(dc_info[0], header=dc_info[1])

    data_channel.send(craft_dc_message(access_token))

    # Send agent session state
    data_channel.send_binary(craft_agent_session_state(session_id))

    # Receive the encrypted data key from the server
    msg = data_channel.recv()
    msg_obj = aws_msg.deserialize(msg)
    if msg_obj.messageType == 'key_exchange':
        content = json.loads(msg_obj.payload)
        encrypted_data_key_b64 = content['Parameters']['DataKey']
        # Decrypt the data key using KMS
        data_key = decrypt_data_key(kms_client, encrypted_data_key_b64)
        print("Data key decrypted successfully.")
    else:
        print("Expected key_exchange message, got:", msg_obj.messageType)
        sys.exit(1)

    # Now we can start sending and receiving encrypted messages
    # Example: send output_stream_data message
    output_message = craft_output_stream_data("$ ", 0)
    # Encrypt the message using the data key
    encrypted_output_message = encrypt_with_data_key(data_key, output_message)
    data_channel.send_binary(encrypted_output_message)

    # Initialize sequence number
    seq_num = 1
    message = ""

    while True:
        # Receive and decrypt message
        encrypted_msg = data_channel.recv()
        decrypted_msg = decrypt_with_data_key(data_key, encrypted_msg)
        msg_obj = aws_msg.deserialize(decrypted_msg)

        if msg_obj.messageType == 'input_stream_data' and msg_obj.sequenceNumber == seq_num:
            payload = msg_obj.payload.decode()
            message += payload
            msg_id = msg_obj.messageId

            # Acknowledge
            ack_msg = craft_acknowledge(msg_id, seq_num)
            encrypted_ack_msg = encrypt_with_data_key(data_key, ack_msg)
            data_channel.send_binary(encrypted_ack_msg)

            # Process input and send response
            if "\r" in payload:
                response_payload = "\r\nCommand received\r\n$ "
                output_msg = craft_output_stream_data(response_payload, seq_num)
                encrypted_output_msg = encrypt_with_data_key(data_key, output_msg)
                data_channel.send_binary(encrypted_output_msg)
            seq_num += 1

        print("Received message:", message)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <kms_key_arn> <region>")
        sys.exit(1)
    kms_key_arn = sys.argv[1]
    region = sys.argv[2]
    main(kms_key_arn, region)