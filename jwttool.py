#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
Process JSON Web Tokens (jwt)
1. Decode a jwt
2. Enconde JSON into a jwt
3. Fuzz a jwt
"""

import jwt
import json
import argparse
import sys

def jwt_decode(jwt_string):
    """ Decode a jwt """
    error_msg = None
    json_jwt = None
    try:
        json_jwt = jwt.decode(jwt_string)
    except jwt.exceptions.DecodeError as error:
        error_msg = error
    try:
        json_jwt = jwt.decode(jwt_string, verify=False)
        error_msg = str(error_msg) + " - Decoding without signature verification."
    except:
        error_msg = sys.exc_info()[0] + " - Could not decode jwt."
    data_dict = {'token':json_jwt, 'error': error_msg};
    return data_dict

def jwt_encode(json_dict):
    """ Encode dict to JSON to a jwt """
    return

def jwt_fuzz(jwt_string):
    """ Fuzz a jwt:
    Decode, update, re-encode and send
    """
    return

def main(options):
    """ code execution """
    print "{0} : {1}".format("fuzz", options.fuzz)
    print "{0} : {1}".format("decode", options.decode)
    print "{0} : {1}".format("encode", options.encode)
    print "{0} : {1}".format("verbosity", options.verbosity)

    if options.decode:
        jwt_input = str(options.decode)
        decoded_dict = jwt_decode(jwt_input)
        if decoded_dict['error']:
            print '\033[93m' + "{0}".format(decoded_dict['error']) + '\033[0m'
        if decoded_dict['token']:
            print "Decoded token: {0}".format(decoded_dict['token'])
        else:
            return
    if options.encode:
        json_input = str(options.encode)
        jwt_encode(dict_input)
    if options.fuzz:
        jwt_input = str(options.fuzz)
        jwt_fuzz(jwt_input)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--decode", help="NOT IMPLEMENTED - Enter a JSON web token to decode",
                        type=str)
    parser.add_argument("-e", "--encode",
                        help="NOT IMPLEMENTED - Enter JSON to encode into web token", type=str)
    parser.add_argument("-f", "--fuzz", help="NOT IMPLEMENTED - Enter a JSON web token to fuzz",
                        type=str)
    parser.add_argument("-v", "--verbosity", help="increase output verbosity",
                        action="store_true")

    args = parser.parse_args()
    main(args)
