#   (c) Copyright 2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
########################################################################################################################

namespace: io.cloudslang.amazon.aws.ec2.tags

imports:
  tags: io.cloudslang.amazon.aws.ec2.tags
  lists: io.cloudslang.base.lists
  strings: io.cloudslang.base.strings

flow:
  name: test_describe_tags

  inputs:
    - endpoint:
        default: ''
        required: false
    - identity
    - credential
    - proxy_host:
        default: ''
        required: false
    - proxy_port:
        default: ''
        required: false
    - proxy_username:
        default: ''
        required: false
    - proxy_password:
        default: ''
        required: false
    - headers:
        default: ''
        required: false
    - query_params:
        default: ''
        required: false
    - delimiter:
        default: ','
        required: false
    - version:
        required: false
    - filter_key:
        default: ''
        required: false
    - filter_resource_id:
        default: ''
        required: false
    - filter_resource_type:
        default: ''
        required: false
    - filter_value:
        default: ''
        required: false
    - max_results:
        default: ''
        required: false
    - next_token:
        default: ''
        required: false

  workflow:
    - describe_tags:
        do:
          tags.describe_tags:
            - endpoint
            - identity
            - credential
            - proxy_host
            - proxy_port
            - proxy_username
            - proxy_password
            - headers
            - query_params
            - delimiter
            - version
            - filter_key
            - filter_resource_id
            - filter_resource_type
            - filter_value
            - max_results
            - next_token
        publish:
          - return_result
          - return_code
          - exception
        navigate:
          - SUCCESS: check_result
          - FAILURE: DESCRIBE_TAGS_FAILURE

    - check_result:
        do:
          lists.compare_lists:
            - list_1: ${str(exception) + "," + return_code}
            - list_2: ",0"
        navigate:
          - SUCCESS: check_describe_tags_message_exist
          - FAILURE: CHECK_RESULT_FAILURE

    - check_describe_tags_message_exist:
        do:
          strings.string_occurrence_counter:
            - string_in_which_to_search: ${return_result}
            - string_to_find: 'DescribeTags'
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: CHECK_DESCRIBE_TAGS_MESSAGE_FAILURE

  results:
    - SUCCESS
    - DESCRIBE_TAGS_FAILURE
    - CHECK_RESULT_FAILURE
    - CHECK_DESCRIBE_TAGS_MESSAGE_FAILURE