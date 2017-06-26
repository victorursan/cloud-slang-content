#   (c) Copyright 2014-2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################

namespace: io.cloudslang.openstack.keypairs

imports:
  keypairs: io.cloudslang.openstack.keypairs

flow:
  name: test_keypairs
  inputs:
    - host
    - identity_port: '5000'
    - compute_port: '8774'
    - username
    - password
    - tenant_name
    - keypair_name
    - public_key:
        required: false

  workflow:
    - create_openstack_keypair:
        do:
          keypairs.create_keypair:
            - host
            - identity_port
            - compute_port
            - username
            - password
            - tenant_name
            - keypair_name
            - public_key
            - proxy_host
            - proxy_port
        publish:
          - return_result
          - error_message
        navigate:
          - SUCCESS: list_keypairs
          - GET_AUTHENTICATION_TOKEN_FAILURE: GET_AUTHENTICATION_TOKEN_FAILURE
          - GET_TENANT_ID_FAILURE: GET_TENANT_ID_FAILURE
          - GET_AUTHENTICATION_FAILURE: GET_AUTHENTICATION_FAILURE
          - CREATE_KEYPAIR_FAILURE: CREATE_KEYPAIR_FAILURE

    - list_keypairs:
        do:
          keypairs.get_keypairs:
            - host
            - username
            - password
            - tenant_name
            - identity_port
            - compute_port
        publish:
          - keypair_list
        navigate:
          - SUCCESS: delete_keypair
          - GET_AUTHENTICATION_TOKEN_FAILURE: GET_AUTHENTICATION_TOKEN_FAILURE
          - GET_TENANT_ID_FAILURE: GET_TENANT_ID_FAILURE
          - GET_AUTHENTICATION_FAILURE: GET_AUTHENTICATION_FAILURE
          - GET_KEYPAIRS_FAILURE: GET_KEYPAIRS_FAILURE
          - EXTRACT_KEYPAIRS_FAILURE: EXTRACT_KEYPAIRS_FAILURE

    - delete_keypair:
        do:
          keypairs.delete_keypair:
            - host
            - username
            - password
            - tenant_name
            - identity_port
            - compute_port
            - keypair_name
        navigate:
          - SUCCESS: SUCCESS
          - GET_AUTHENTICATION_TOKEN_FAILURE: GET_AUTHENTICATION_TOKEN_FAILURE
          - GET_TENANT_ID_FAILURE: GET_TENANT_ID_FAILURE
          - GET_AUTHENTICATION_FAILURE: GET_AUTHENTICATION_FAILURE
          - DELETE_KEYPAIR_FAILURE: DELETE_KEYPAIR_FAILURE

  outputs:
    - keypair_list
  results:
    - SUCCESS
    - GET_AUTHENTICATION_FAILURE
    - GET_AUTHENTICATION_TOKEN_FAILURE
    - GET_TENANT_ID_FAILURE
    - CREATE_KEYPAIR_FAILURE
    - GET_KEYPAIRS_FAILURE
    - EXTRACT_KEYPAIRS_FAILURE
    - DELETE_KEYPAIR_FAILURE
