########################################################################################################################
#!!
#! @description: This flow is used to validate the response returned by Zabbix, checking the statusCode and 
#!               responseBody of the request. The statusCode should be greater than minAcceptedValue, less than 
#!               maxAcceptedValue and the jsonBody should be a json without the field "error.data"
#!
#! @input json_body: The response body returned by the request to the Zabbix server.
#! @input status_code: The status code of the request to the Zabbix server.
#! @input min_accepted_value: The minimum (including) statusCode accepted as valid.
#! @input max_accepted_value: The maximum (excluded) statusCode accepted as valid.
#!
#! @output return_result: This will contain the response message. In case of an error this output will contain the 
#!                        error message.
#! @output specific_error: Generated description
#!
#! @result SUCCESS: The flow has run as the description states.
#! @result FAILURE: An exception occured.
#!!#
########################################################################################################################

namespace: io.cloudslang.zabbix.utilities

imports:
  json: io.cloudslang.base.json
  math: io.cloudslang.base.math
  utils: io.cloudslang.base.utils
  http:  io.cloudslang.base.http

flow: 
  name: check_zabbix_response
  
  inputs: 
    - json_body    
    - status_code    
    - min_accepted_value: 
        default: '200'  
        required: false  
    - max_accepted_value: 
        default: '300'  
        required: false  
    
  workflow: 
    - is_status_code_greater_or_equal_than_minimum_accepted:
        do:
          math.compare_numbers:
            - value1: ${ status_code }
            - value2: ${ min_accepted_value }
        navigate:
          - GREATER_THAN: is_status_code_less_than_maximum
          - EQUALS: is_status_code_less_than_maximum
          - LESS_THAN: set_failure_message
        
    - is_status_code_less_than_maximum:
        do:
           math.compare_numbers:
            - value1: ${ status_code }
            - value2: ${ max_accepted_value }
        navigate:
          - LESS_THAN: check_for_errors
          - EQUALS: set_failure_message
          - GREATER_THAN: set_failure_message

    - set_failure_message:
        do:
          utils.noop:
            - text:  ${ specific_error }
        publish:
          - return_result: ${ text }
        navigate:
          - SUCCESS: FAILURE
        
    - check_for_errors:
        do:
          json.json_path_query:
            - json_object: ${ json_body }
            - json_path: 'error.data'
        publish: 
          - specific_error:  ${ return_result }
        navigate: 
          - SUCCESS: set_failure_message
          - FAILURE: set_success_message

    - set_success_message:
        do:
          utils.noop:
            - text: 'Zabbix response is valid and contains no errors.'
        publish:
          - return_result: ${ text }
        navigate:
          - SUCCESS: SUCCESS
        
  outputs: 
    - return_result
    - specific_error
  
  results: 
    - SUCCESS
    - FAILURE

