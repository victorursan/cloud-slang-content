#   (c) Copyright 2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
namespace: io.cloudslang.base.datetime

imports:
  datetime: io.cloudslang.base.datetime
  strings: io.cloudslang.base.strings

flow:
  name: test_parse_date

  inputs:
    - date: |
        'Wed, Jul 4, '01'
    - date_format:
        default: 'EEE, MMM d, ''yy'
        required: false
    - date_locale_lang:
        default: 'en'
        required: false
    - date_locale_country:
        default: 'US'
        required: false
    - out_format:
        default: 'EEE, MMM d, ''yy'
        required: false
    - out_locale_lang:
        default: 'it'
        required: false
    - out_locale_country:
        default: 'IT'
        required: false

  workflow:
    - execute_parse_date:
        do:
          datetime.parse_date:
            - date
            - date_format
            - date_locale_lang
            - date_locale_country
            - out_format
            - out_locale_lang
            - out_locale_country
        publish:
            - output
        navigate:
            - SUCCESS: verify_against_expected_result
            - FAILURE: PARSE_DATE_FAILURE

    - verify_against_expected_result:
        do:
          strings.string_equals:
            - first_string: 'mer, lug 4, ''01'
            - second_string: ${output}
        navigate:
            - SUCCESS: SUCCESS
            - FAILURE: INCORRECT_OUTPUT

  results:
    - SUCCESS
    - PARSE_DATE_FAILURE
    - INCORRECT_OUTPUT
