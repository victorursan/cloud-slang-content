#   (c) Copyright 2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
namespace: io.cloudslang.twilio.sms
flow:
  name: test_send_sms_and_get_responses_with_files
  inputs:
    - recipients_file
    - responses_file
  workflow:
    - send_sms_and_get_responses_with_files:
        do:
          io.cloudslang.twilio.sms.send_sms_and_get_responses_with_files:
            - recipients_file: ${recipients_file}
            - responses_file: ${responses_file}
            - message: 'How many will attend?'
            - account_sid: ${get_sp('io.cloudslang.twilio.sms.account_sid')}
            - auth_token: ${get_sp('io.cloudslang.twilio.sms.auth_token')}
            - twilio_num: ${get_sp('io.cloudslang.twilio.sms.twilio_phone_number')}
            - proxy_host: ${get_sp('io.cloudslang.twilio.sms.proxy_host')}
            - proxy_port: ${get_sp('io.cloudslang.twilio.sms.proxy_port')}
        navigate:
          - FAILURE: FAILURE
          - SUCCESS: SUCCESS
  results:
    - FAILURE
    - SUCCESS
