#   (c) Copyright 2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
#!!
#! @description: Performs a REST API call to get a list of all the existing builds of a specified Heroku application.
#!
#! @input username: Heroku username
#!                  example: 'someone@mailprovider.com'
#! @input password: Heroku password used for authentication
#! @input app_id_or_name: ID or name of the Heroku application
#!
#! @output return_result: response of the operation in case of success, error message otherwise
#! @output error_message: return_result if status_code is not '200'
#! @output return_code: '0' if success, '-1' otherwise
#! @output status_code: code returned by the operation
#!
#! @result SUCCESS: Heroku application builds retrieved successfully
#! @result FAILURE: There was an error while trying to retrieve Heroku application builds
#!!#
########################################################################################################################

namespace: io.cloudslang.heroku.builds

imports:
  rest: io.cloudslang.base.http

flow:
  name: get_application_builds

  inputs:
    - username:
        sensitive: true
    - password:
        sensitive: true
    - app_id_or_name

  workflow:
    - get_application_builds:
        do:
          rest.http_client_get:
            - url: ${'https://api.heroku.com/apps/' + app_id_or_name + '/builds'}
            - username
            - password
            - headers: "Accept:application/vnd.heroku+json; version=3"
            - content_type: "application/json"

        publish:
          - return_result
          - error_message
          - return_code
          - status_code

  outputs:
    - return_result
    - error_message
    - return_code
    - status_code
