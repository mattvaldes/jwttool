#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
Process JSON Web Tokens (jwt)
1. Decode a jwt
2. Encode JSON into a jwt
3. Fuzz a jwt
"""

import jwt
import argparse
import sys
import ast

def jwt_decode(jwt_string, jwt_secret):
    """ Decode a jwt """
    error_msg = None
    json_jwt = None
    if jwt_secret:
        """If given a secret, try decoding with secret"""
        try:
            json_jwt = jwt.decode(jwt_string, jwt_secret)
        except jwt.exceptions.DecodeError as error:
            error_msg = str(error) + " - Decoding failed. Given secret is incorrect."
    else:
        try:
            """Decode given no secret
            We are assuming jwt is not signed"""
            json_jwt = jwt.decode(jwt_string)
        except jwt.exceptions.DecodeError as error:
            error_msg = str(error)
        except jwt.exceptions.ExpiredSignatureError as error:
            error_msg = str(error)
        except:
            error_msg = str(sys.exc_info()[0])
    if error_msg:
        try:
            """Decode without signature verification
            We are assuming jwt decode failed above due to signature
            and we don't have the secret"""
            json_jwt = jwt.decode(jwt_string, verify=False)
            error_msg = "Decoding without signature verification." + error_msg
        except:
            error_msg = "Could not decode jwt. - " + str(sys.exc_info()[0])
    data_dict = {'token':json_jwt, 'error': error_msg}
    return data_dict

def jwt_encode(json_string, headers_string):
    """ Encode dict to JSON to a jwt """
    error_msg = None
    encoded_jwt = None
    json_object = ast.literal_eval(json_string)
    if headers_string:
        headers = ast.literal_eval(headers_string)
        try:
            """Encode with no secret"""
            encoded_jwt = jwt.encode(json_object, '', algorithm='HS256', headers=headers)
        except TypeError as error:
            error_msg = "Could not encode data provided. - " + str(error)
    else:
        try:
            """Encode with no secret"""
            encoded_jwt = jwt.encode(json_object, '')
        except TypeError as error:
            error_msg = "Could not encode data provided. - " + str(error)
    data_dict = {'token':encoded_jwt, 'error': error_msg}
    return data_dict

def jwt_fuzz(jwt_string):
    """ Fuzz a jwt:
    Decode, update, re-encode and send
    """
    return

def main(options):
    """ code execution """
    print "Options provided:"
    print "{0} : {1}".format("fuzz", options.fuzz)
    print "{0} : {1}".format("decode", options.decode)
    print "{0} : {1}".format("encode", options.encode)
    print "{0} : {1}".format("secret", options.secret)
    print "{0} : {1}".format("verbosity", options.verbosity)

    if options.decode:
        if options.secret:
            decoded_dict = jwt_decode(str(options.decode), str(options.secret))
        else:
            decoded_dict = jwt_decode(str(options.decode), options.secret)
        if decoded_dict['error']:
            print '\033[93m' + "{0}".format(decoded_dict['error']) + '\033[0m'
        if decoded_dict['token']:
            print "Decoded token: {0}".format(decoded_dict['token'])
        else:
            return
    if options.encode:
        json_string = options.encode
        headers_string = None
        if options.headers:
            headers_string = str(options.headers)
        encoded_dict = jwt_encode(json_string, headers_string)
        if encoded_dict['error']:
            print '\033[93m' + "{0}".format(encoded_dict['error']) + '\033[0m'
        if encoded_dict['token']:
            print "Encoded token: {0}".format(encoded_dict['token'])
        else:
            return
    if options.fuzz:
        jwt_input = str(options.fuzz)
        jwt_fuzz(jwt_input)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--decode", help="NOT IMPLEMENTED - Enter a JSON web token to decode",
                        type=str)
    parser.add_argument("-e", "--encode",
                        help="Enter JSON to encode into web token", type=str)
    parser.add_argument("-a", "--headers",
                        help="NOT IMPLEMENTED - (Requires -e) Headers to add in the web token",
                        type=str)
    parser.add_argument("-s", "--secret",
                        help="NOT IMPLEMENTED - Enter secret to decode or encode web token",
                        type=str)
    parser.add_argument("-f", "--fuzz", help="NOT IMPLEMENTED - Enter a JSON web token to fuzz",
                        type=str)
    parser.add_argument("-v", "--verbosity", help="increase output verbosity",
                        action="store_true")

    args = parser.parse_args()
    main(args)
