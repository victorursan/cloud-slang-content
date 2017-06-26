#   (c) Copyright 2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Created by Florian TEISSEDRE - florian.teissedre@hpe.com
####################################################
namespace: io.cloudslang.heroku.collaborators

imports:
  collaborators: io.cloudslang.heroku.collaborators
  lists: io.cloudslang.base.lists
  strings: io.cloudslang.base.strings

flow:
  name: test_create_application_collaborator

  inputs:
    - username
    - password
    - app_id_or_name
    - user
    - silent:
        default: 'False'
        required: false

  workflow:
    - create_application_collaborator:
        do:
          collaborators.create_application_collaborator:
            - username
            - password
            - app_id_or_name
            - user
            - silent
        publish:
          - return_result
          - error_message
          - return_code
          - status_code
          - id
          - created_at
        navigate:
          - SUCCESS: check_result
          - ADD_SILENT_VALUE_FAILURE: ADD_SILENT_VALUE_FAILURE
          - INSERT_USER_VALUE_FAILURE: INSERT_USER_VALUE_FAILURE
          - CREATE_APPLICATION_COLLABORATOR_FAILURE: CREATE_APPLICATION_COLLABORATOR_FAILURE
          - GET_ID_FAILURE: GET_ID_FAILURE
          - GET_CREATED_AT_FAILURE: GET_CREATED_AT_FAILURE

    - check_result:
        do:
          lists.compare_lists:
            - list_1: ${str(error_message) + "," + return_code + "," + status_code}
            - list_2: ",0,201"
        navigate:
          - SUCCESS: check_id_is_present
          - FAILURE: CHECK_RESULT_FAILURE

    - check_id_is_present:
        do:
          strings.string_equals:
            - first_string: ${id}
            - second_string: None
        navigate:
          - SUCCESS: ID_IS_NOT_PRESENT
          - FAILURE: check_created_at_is_present

    - check_created_at_is_present:
        do:
          strings.string_equals:
            - first_string: ${created_at}
            - second_string: None
        navigate:
          - SUCCESS: CREATED_AT_IS_NOT_PRESENT
          - FAILURE: SUCCESS

  outputs:
    - return_result
    - error_message
    - return_code
    - status_code
    - id
    - created_at

  results:
    - SUCCESS
    - ADD_SILENT_VALUE_FAILURE
    - INSERT_USER_VALUE_FAILURE
    - CREATE_APPLICATION_COLLABORATOR_FAILURE
    - GET_ID_FAILURE
    - GET_CREATED_AT_FAILURE
    - CHECK_RESULT_FAILURE
    - ID_IS_NOT_PRESENT
    - CREATED_AT_IS_NOT_PRESENT
