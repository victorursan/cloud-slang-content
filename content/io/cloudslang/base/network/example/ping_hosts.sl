#   (c) Copyright 2014-2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
#!!
#! @description: Pings addresses from input list and sends an email with results.
#!
#! @prerequisites: System property file with email properties
#!
#! @input ip_list: List of IPs to be checked.
#! @input message_body: The message to be sent in emails.
#!                      Default: ''
#! @input all_nodes_are_up: Whether the nodes are up or not.
#!                          Default: 'true'
#! @input hostname: email host - System Property: io.cloudslang.base.hostname
#! @input port: email port - System Property: io.cloudslang.base.port
#! @input from: email sender - System Property: io.cloudslang.base.from
#! @input to: email recipient - System Property: io.cloudslang.base.to
#! @input subject: Email subject.
#!                 Default: "Ping Result"
#! @input username: Optional - Username to connect to email host.
#! @input password: Optional - Password for the username to connect to email host.
#!
#! @result SUCCESS: Addressee will get an email with result.
#! @result FAILURE: Addressee will get an email with exception of operation.
#!!#
########################################################################################################################

namespace: io.cloudslang.base.network.example

imports:
  network: io.cloudslang.base.network
  mail: io.cloudslang.base.mail
  strings: io.cloudslang.base.strings

flow:
  name: ping_hosts

  inputs:
    - ip_list
    - message_body:
        default: ''
        required: false
    - all_nodes_are_up:
        default: 'true'
    - hostname: ${get_sp('io.cloudslang.base.hostname')}
    - port: ${get_sp('io.cloudslang.base.port')}
    - from: ${get_sp('io.cloudslang.base.from')}
    - to: ${get_sp('io.cloudslang.base.to')}
    - subject:
        default: 'Ping Result'
    - username:
        default: ${get_sp('io.cloudslang.base.username')}
        required: false
    - password:
        default: ${get_sp('io.cloudslang.base.password')}
        required: false
        sensitive: true

  workflow:
    - check_address:
        loop:
          for: address in ip_list
          do:
            network.ping:
              - address
              - message_body
              - all_nodes_are_up
        publish:
          - messagebody: ${ message_body + message }
          - all_nodes_are_up: ${ str(all_nodes_are_up.lower() == 'true' and is_up.lower() == 'true') }
        navigate:
          - UP: check_result
          - DOWN: failure_mail_send
          - FAILURE: failure_mail_send

    - check_result:
        do:
          strings.string_equals:
            - first_string: ${ all_nodes_are_up }
            - second_string: "True"
        navigate:
          - SUCCESS: mail_send
          - FAILURE: failure_mail_send

    - mail_send:
        do:
          mail.send_mail:
            - hostname
            - port
            - from
            - to
            - subject
            - body: "${ 'Result: ' + message_body }"
            - username
            - password

    - on_failure:
        - failure_mail_send:
            do:
              mail.send_mail:
                - hostname
                - port
                - from
                - to
                - subject
                - body: "${ 'Result: Failure to ping: ' + message_body }"
                - username
                - password
