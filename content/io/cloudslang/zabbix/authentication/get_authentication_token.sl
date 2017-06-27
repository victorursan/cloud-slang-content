########################################################################################################################
#!!
#! @description: This flow is used to retrieve an authentication token for a specific Zabbix user based on its username 
#!               and password.
#!
#! @input zabbix_host: The Zabbix host.
#! @input zabbix_port: The Zabbix port.
#! @input zabbix_protocol: The protocol used for connection with Zabbix host.
#! @input zabbix_username: The username used for authentication to the Zabbix host.
#! @input zabbix_password: The password associated with zabbixUsername.
#! @input auth_type: The type of authentication used by this operation when trying to execute the request on the target 
#!                   server. The authentication is not preemptive: a plain request not including authentication info 
#!                   will be made and only when the server responds with a 'WWW-Authenticate' header the client will 
#!                   send required headers. If the server needs no authentication but you specify one in this input the 
#!                   request will work nevertheless. The client cannot choose the authentication method and there is no 
#!                   fallback so you have to know which one you need. If the web application and proxy use different 
#!                   authentication types, these must be specified like in the Example model.
#! @input proxy_host: The proxy server used to access the web site.
#! @input proxy_port: The proxy server port. When the value is '-1' the default port of the scheme, specified in the '
#!                    proxyHost', will be used.
#! @input proxy_username: The user name used when connecting to the proxy. The 'authType' input will be used to choose 
#!                        authentication type. The 'Basic' and 'Digest' proxy authentication type are supported.
#! @input proxy_password: The proxy server password associated with the proxyUsername input value.
#! @input trust_all_roots: Specifies whether to enable weak security over SSL/TSL. A certificate is trusted even if no 
#!                         trusted certification authority issued it.
#! @input certificate_hostname_verifier: Specifies the way the server hostname must match a domain name in the subject'
#!                                       s Common Name (CN) or subjectAltName field of the X.509 certificate. The 
#!                                       hostname verification system prevents communication with other hosts other 
#!                                       than the ones you intended. This is done by checking that the hostname is in 
#!                                       the subject alternative name extension of the certificate. This system is 
#!                                       designed to ensure that, if an attacker(Man In The Middle) redirects traffic 
#!                                       to his machine, the client will not accept the connection. If you set this 
#!                                       input to "allow_all", this verification is ignored and you become vulnerable 
#!                                       to security attacks. For the value "browser_compatible" the hostname verifier 
#!                                       works the same way as Curl and Firefox. The hostname must match either the 
#!                                       first CN, or any of the subject-alts. A wildcard can occur in the CN, and in 
#!                                       any of the subject-alts. The only difference between "browser_compatible" and 
#!                                       strict" is that a wildcard (such as "*.foo.com") with "browser_compatible" 
#!                                       matches all subdomains, including "a.b.foo.com". From the security perspective,
#!                                       to provide protection against possible Man-In-The-Middle attacks, we strongly 
#!                                       recommend to use "strict" option.
#! @input trust_keystore: The pathname of the Java TrustStore file. This contains certificates from other parties that 
#!                        you expect to communicate with, or from Certificate Authorities that you trust to identify 
#!                        other parties.  If the protocol (specified by the 'url') is not 'https' or if trustAllRoots 
#!                        is 'true' this input is ignored.
#! @input trust_password: The password associated with the TrustStore file.
#! @input keystore: The pathname of the Java KeyStore file. You only need this if the server requires client 
#!                  authentication. If the protocol (specified by the 'url') is not 'https' or if trustAllRoots is '
#!                  true' this input is ignored.
#! @input keystore_password: The password associated with the KeyStore file.
#! @input connect_timeout: The time to wait for a connection to be established, in seconds. A timeout value of '0' 
#!                         represents an infinite timeout.
#! @input socket_timeout: The timeout for waiting for data (a maximum period inactivity between two consecutive data 
#!                        packets), in seconds. A socketTimeout value of '0' represents an infinite timeout.
#! @input use_cookies: Specifies whether to enable cookie tracking or not. Cookies are stored between consecutive calls 
#!                     in a serializable session object therefore they will be available on a branch level (same 
#!                     subflow, same lane). If you specify a non-boolean value, the default value is used.
#! @input keep_alive: Specifies whether to create a shared connection that will be used in subsequent calls. If 
#!                    keepAlive is false, the already open connection will be used and after execution it will close it.
#!                    The operation will use a connection pool stored in a GlobalSessionObject that will be available 
#!                    throughout the execution (the flow and subflows, between parallel split lanes)
#! @input connections_max_per_route: The maximum limit of connections on a per route basis. The default will create no 
#!                                   more than 2 concurrent connections per given route.
#! @input connections_max_total: The maximum limit of connections in total. The default will create no more than 20 
#!                               concurrent connections in total.
#!
#! @output json_result: Generated description
#! @output status_code: Generated description
#! @output return_result: This will contain the response message. In case of an error this output will contain the 
#!                        error message.
#! @output zabbix_token: Zabbix token that can be used for authentication with other Zabbix related flows.
#!
#! @result SUCCESS: The flow has run as the description states.
#! @result FAILURE: An exception occurred.
#!!#
########################################################################################################################

namespace: io.cloudslang.content.zabbix.authentication

imports:
  http:  io.cloudslang.base.http
  json:  io.cloudslang.base.json
  print: io.cloudslang.base.print
  utils: io.cloudslang.base.utils

flow: 
  name: get_authentication_token
  
  inputs: 
    - zabbix_host    
    - zabbix_port: 
        default: '443'    
    - zabbix_protocol: 
        default: 'https'    
    - zabbix_username    
    - zabbix_password:    
        sensitive: true
    - auth_type: 
        default: 'Basic'  
        required: false  
    - proxy_host:  
        required: false  
    - proxy_port: 
        default: '8080'  
        required: false  
    - proxy_username:  
        required: false  
    - proxy_password:  
        required: false  
        sensitive: true
    - trust_all_roots: 
        default: 'false'  
        required: false  
    - certificate_hostname_verifier: 
        default: 'strict'  
        required: false  
    - trust_keystore:  
        required: false  
    - trust_password: 
        default: ''
        required: false  
        sensitive: true
    - keystore:  
        required: false  
    - keystore_password: 
        default: ''
        required: false  
        sensitive: true
    - connect_timeout: 
        default: '10'  
        required: false  
    - socket_timeout: 
        default: '0'  
        required: false  
    - use_cookies: 
        default: 'true'  
        required: false  
    - keep_alive: 
        default: 'true'  
        required: false  
    - connections_max_per_route: 
        default: '2'  
        required: false  
    - connections_max_total: 
        default: '20'  
        required: false  
    
  workflow: 
    - get_zabbix_authentication_token:
        do:
          http.http_client_post:
            - url: ${zabbix_protocol + '://' + zabbix_host + ':' + zabbix_port + '/zabbix/api_jsonrpc.php'} 
            - body: >
                 ${'{"jsonrpc": "2.0","method": "user.login","params":{"user": "' + zabbix_username + '","password": "' + zabbix_password + '"},"id": 1,"auth": null}'}
            - content_type: 'application/json-rpc' 
            - auth_type
            - proxy_host
            - proxy_port
            - proxy_username
            - proxy_password
            - trust_all_roots
            - x_509_hostname_verifier: ${ certificate_hostname_verifier } 
            - trust_keystore
            - trust_password
            - keystore
            - keystore_password
            - connect_timeout
            - socket_timeout
            - use_cookies
            - keep_alive
            - connections_max_per_route
            - connections_max_total
        publish: 
          - json_result: ${return_result}
          - status_code
          - error_message
        navigate:
          - SUCCESS: check_for_errors
          - FAILURE: set_failure_message

    - extract_token:
        do:
          json.json_path_query:
            - json_object: ${json_result}
            - json_path: 'result'
        publish:
          - zabbix_token: ${return_result}
          - exception
        navigate:
          - SUCCESS: set_success_message
          - FAILURE: set_failure_message

    - set_success_message:
        do:
          utils.noop:
            - text: 'Successfully retrieved an authentication token.'
        publish:
          - return_result: ${ text }
        navigate:
          - SUCCESS: SUCCESS

    - check_for_errors:
        do:
          json.json_path_query:
            - json_object: ${ json_result }
            - json_path: 'error.data'
        publish:
          - specific_error:  ${ return_result }
        navigate:
          - SUCCESS: set_failure_message
          - FAILURE: extract_token

    - set_failure_message:
        do:
          utils.noop:
            - text: 'Unable to retrieve an authentication token.'
        publish:
          - return_result: ${ text }
        navigate:
          - SUCCESS: FAILURE

  outputs: 
    - json_result
    - status_code
    - return_result
    - zabbix_token
    - specific_error
  
  results: 
    - SUCCESS
    - FAILURE

