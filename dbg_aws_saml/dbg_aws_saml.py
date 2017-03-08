#!/usr/bin/env python
from __future__ import print_function

import base64
import datetime
import getpass
import json
import pickle
import sys
# noinspection PyPep8Naming
import xml.etree.ElementTree as ET

import boto3
import requests
from bs4 import BeautifulSoup

debug = False

# Fix Python 2.x.
try:
    # noinspection PyShadowingBuiltins
    input = raw_input
except NameError:
    pass


# noinspection PyPep8Naming
def auth_cached():
    try:
        with open('assumedRole.pkl', 'rb') as assumed_file:
            assumedRoleObject = pickle.load(assumed_file)

        credentials = assumedRoleObject['Credentials']
    except:
        return None

    return credentials


def auth_live():
    url = 'https://amplis.deutsche-boerse.com/auth/json/authenticate'
    payload = {'realm': '/internet', 'spEntityID': 'urn:amazon:webservices'}
    headers = {'Content-Type': 'application/json'}

    try:
        r1 = requests.post(url, params=payload, headers=headers)
        r1j = r1.json()
        if debug:
            print('Url:         ' + r1.url)
            print('Status Code: ' + str(r1.status_code))
            print('Reason:      ' + r1.reason)
            # print('Text:        ' + r1.text)
            print('Headers:     ' + str(r1.headers))
            print('Text:')
            print(json.dumps(r1j, indent=2))
    except:
        print('Request failed, check network connection!')
        return None

    try:
        r1j['callbacks'][0]['input'][0]['value'] = input('Username: ')  # should locate 'IDToken1'
        r1j['callbacks'][1]['input'][0]['value'] = input('MFA token: ')  # should locate 'IDToken2'
        r1j['callbacks'][2]['input'][0]['value'] = getpass.getpass('Password: ')  # should locate 'IDToken3'
        if debug:
            print(json.dumps(r1j, indent=2))
    except:
        print('No valid form to fill returned')
        return None

    try:
        r2 = requests.post(url, params=payload, headers=headers, data=json.dumps(r1j))
        r2j = r2.json()
        if debug:
            print('Url:        ' + r2.url)
            print('Status Code:' + str(r2.status_code))
            print('Reason:     ' + r2.reason)
            # print('Text:       ' + r2.text)
            print('Headers:    ' + str(r2.headers))
            print('Text:')
            print(json.dumps(r2j, indent=2))
    except:
        print('Request failed, check network connection!')
        return None

    try:
        token = r2j['tokenId']
    except:
        print('Authentication failed!')
        return None

    if debug:
        print('Extracted token: ' + token)

    if debug:  # some interesting debug code
        url = 'https://amplis.deutsche-boerse.com/auth/json/users'
        payload = {'realm': '/internet', '_action': 'idFromSession'}
        headers = {'Content-Type': 'application/json', 'Cookie': 'es=' + token}

        try:
            r3 = requests.post(url, params=payload, headers=headers)
            r3j = r3.json()
            print('Url:         ' + r3.url)
            print('Status Code: ' + str(r3.status_code))
            print('Reason:      ' + r3.reason)
            # print('Text:        ' + r3.text)
            print('Headers:     ' + str(r3.headers))
            print('Text:')
            print(json.dumps(r3j, indent=2))
        except:
            print('Request failed, check network connection!')
            return None

        my_id = r3j['id']
        if debug:
            print('Extracted id: ' + my_id)

        url = 'https://amplis.deutsche-boerse.com/auth/json/users/' + my_id
        payload = {'realm': '/internet'}
        headers = {'Content-Type': 'application/json', 'Cookie': 'es=' + token}

        r4 = requests.get(url, params=payload, headers=headers)
        r4j = r4.json()
        print('Url:         ' + r4.url)
        print('Status Code: ' + str(r4.status_code))
        print('Reason:      ' + r4.reason)
        # print('Text:        ' + r4.text)
        print('Headers:     ' + str(r4.headers))
        print(json.dumps(r4j, indent=2))

    url = 'https://amplis.deutsche-boerse.com/auth/saml2/jsp/idpSSOInit.jsp'
    payload = {'metaAlias': '/internet/idp', 'spEntityID': 'urn:amazon:webservices', 'redirected': 'true'}
    headers = {'Cookie': 'es=' + token,
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
               'Accept-Encoding': 'gzip, deflate, br',
               'Accept-Language': 'de,en-US;q=0.7,en;q=0.3'}

    r5 = requests.get(url, params=payload, headers=headers)
    if debug:
        print('Url:         ' + r5.url)
        print('Status Code: ' + str(r5.status_code))
        print('Reason:      ' + r5.reason)
        print('Text:        ' + r5.text)
        print('Headers:     ' + str(r5.headers))

    # Python2 compatibility fix
    try:
        r5_text = r5.text.decode('utf8')
    except AttributeError:
        r5_text = r5.text
    soup = BeautifulSoup(r5_text, 'html.parser')
    assertion = ''

    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if inputtag.get('name') == 'SAMLResponse':
            if debug:
                print(inputtag.get('value'))
            assertion = inputtag.get('value')

    if debug:
        print(base64.b64decode(assertion))

    # Parse the returned assertion and extract the authorized roles
    awsroles = []
    root = ET.fromstring(base64.b64decode(assertion))
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role':
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                awsroles.append(saml2attributevalue.text)

    # Note the format of the attribute value should be role_arn,principal_arn
    # but lots of blogs list it as principal_arn,role_arn so let's reverse
    # them if needed
    for awsrole in awsroles:
        chunks = awsrole.split(',')
        if 'saml-provider' in chunks[0]:
            newawsrole = chunks[1] + ',' + chunks[0]
            index = awsroles.index(awsrole)
            awsroles.insert(index, newawsrole)
            awsroles.remove(awsrole)

    # If I have more than one role, ask the user which one they want,
    # otherwise just proceed
    if debug:
        print("Number of awsroles found: " + str(len(awsroles)))
    if len(awsroles) > 1:
        i = 0
        print("Please choose the role you would like to assume:")
        for awsrole in awsroles:
            print('[', i, ']: ', awsrole.split(',')[0])
            i += 1
        print("Selection: ", )
        selectedroleindex = input()

        # Basic sanity check of input
        if int(selectedroleindex) > (len(awsroles) - 1):
            print('You selected an invalid role index, please try again')
            sys.exit(0)

        role_arn = awsroles[int(selectedroleindex)].split(',')[0]
        principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
    else:
        role_arn = awsroles[0].split(',')[0]
        principal_arn = awsroles[0].split(',')[1]

    if debug:
        print("Role ARN:      " + role_arn)
        print("Principal ARN: " + principal_arn)

    client = boto3.client('sts')
    # noinspection PyPep8Naming
    assumedRoleObject = client.assume_role_with_saml(
        RoleArn=role_arn,
        PrincipalArn=principal_arn,
        SAMLAssertion=assertion
    )

    with open('assumedRole.pkl', 'wb') as output:
        pickle.dump(assumedRoleObject, output, pickle.HIGHEST_PROTOCOL)

    credentials = assumedRoleObject['Credentials']
    return credentials


def main():
    # Iterate over credentials functions
    ret_code = 1
    for fun in [auth_cached, auth_live]:
        credentials = fun()

        try:
            aws_access_key_id = credentials['AccessKeyId'],
            aws_secret_access_key = credentials['SecretAccessKey']
            aws_session_token = credentials['SessionToken']

            exp = credentials['Expiration'].replace(tzinfo=None)
            now = datetime.datetime.now()
            diff = exp - now + datetime.timedelta(hours=1)

            if diff.total_seconds() < 0:
                continue

            print('Key ID:        ' + str(aws_access_key_id[0]))
            print('Access Key:    ' + str(aws_secret_access_key))
            print('Session Token: ' + str(aws_session_token))
            print('Expiration:    ' + str(credentials['Expiration'].replace(tzinfo=None)))
            print('Expiration (in UTC):    ' + str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S%z')))
            print('Until expiration:    ' + str(diff))
            print('')

            print('export AWS_ACCESS_KEY_ID=\'' + str(
                aws_access_key_id[0]) + '\' && export AWS_SECRET_ACCESS_KEY=\'' + str(
                aws_secret_access_key) + '\' && export AWS_SESSION_TOKEN=\'' + str(
                aws_session_token) + '\' && export AWS_SECURITY_TOKEN=\'' + str(aws_session_token) + '\'')

            break
        except Exception:
            continue

    sys.exit(ret_code)


if __name__ == "__main__":
    # execute only if run as a script
    main()
