#   (c) Copyright 2016 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
#!!
#! @description: Performs an HTTP request to save an image that is associated with a generalized virtual machine
#!
#! @input subscription_id: The ID of the Azure Subscription on which the VM should be created.
#! @input api_version: The API version used to create calls to Azure
#! @input auth_type: optional - authentication type
#!                   Default: "anonymous"
#! @input auth_token: authentication token
#! @input vhd_prefix: Specifies the prefix in the name of the blobs that will constitute the storage profile of the image
#! @input destination_container_name: Specifies the name of the container inside which the vhds constituting the image will reside
#! @input override_vhds: Specifies if an existing vhd with same prefix inside the destination container is overwritten
#!                       Default: 'true'
#! @input resource_group_name: The name of the Azure Resource Group that should be used to create the VM.
#! @input virtual_machine_name: virtual machine name
#! @input content_type: optional - content type that should be set in the request header, representing the MIME-type
#!                      of the data in the message body
#!                      Default: "application/json; charset=utf-8"
#! @input trust_keystore: optional - the pathname of the Java TrustStore file. This contains certificates from other parties
#!                        that you expect to communicate with, or from Certificate Authorities that you trust to
#!                        identify other parties.  If the protocol (specified by the 'url') is not 'https' or if
#!                        trust_all_roots is 'true' this input is ignored.
#!                        Default value: ..JAVA_HOME/java/lib/security/cacerts
#!                        Format: Java KeyStore (JKS)
#! @input trust_password: optional - the password associated with the Trusttore file. If trust_all_roots is false and trust_keystore is empty,
#!                        trustPassword default will be supplied.
#!                        Default value: ''
#! @input keystore: optional - the pathname of the Java KeyStore file. You only need this if the server requires client authentication.
#!                  If the protocol (specified by the 'url') is not 'https' or if trustAllRoots is 'true' this input is ignored.
#!                  Default value: ..JAVA_HOME/java/lib/security/cacerts
#!                  Format: Java KeyStore (JKS)
#! @input keystore_password: optional - the password associated with the KeyStore file. If trust_all_roots is false and keystore
#!                           is empty, keystore_password default will be supplied.
#!                           Default value: ''
#! @input trust_all_roots: optional - specifies whether to enable weak security over SSL - Default: false
#! @input x_509_hostname_verifier: optional - specifies the way the server hostname must match a domain name in the subject's
#!                                 Common Name (CN) or subjectAltName field of the X.509 certificate
#!                                 Valid: 'strict', 'browser_compatible', 'allow_all' - Default: 'allow_all'
#!                                 Default: 'strict'
#! @input proxy_host: optional - proxy server used to access the web site
#! @input proxy_port: optional - proxy server port - Default: '8080'
#! @input proxy_username: optional - username used when connecting to the proxy
#! @input proxy_password: optional - proxy server password associated with the <proxy_username> input value
#! @input connections_max_per_root: optional - maximum limit of connections on a per route basis - Default: '50'
#! @input connections_max_total: optional - maximum limit of connections in total - Default: '500'
#! @input preemptive_auth: optional - if 'true' authentication info will be sent in the first request, otherwise a request
#!                         with no authentication info will be made and if server responds with 401 and a header
#!                         like WWW-Authenticate: Basic realm="myRealm" only then will the authentication info
#!                         will be sent - Default: true
#! @input use_cookies: optional - specifies whether to enable cookie tracking or not - Default: true
#! @input keep_alive: optional - specifies whether to create a shared connection that will be used in subsequent calls
#!                    Default: true
#! @input request_character_set: optional - character encoding to be used for the HTTP request - Default: 'UTF-8'
#! @input chunked_request_entity: optional - data is sent in a series of 'chunks' - Valid: true/false
#!                                Default: "false"
#!
#! @output output: Result of the operation
#! @output status_code: 200 if request completed successfully, others in case something went wrong
#!
#! @result SUCCESS: virtual machine image saved successfully.
#! @result FAILURE: There was an error while trying to save the virtual machine image.
#!!#
########################################################################################################################

namespace: io.cloudslang.microsoft.azure.compute.virtual_machines

imports:
  http: io.cloudslang.base.http
  strings: io.cloudslang.base.strings

flow:
  name: save_image_from_vm

  inputs:
    - subscription_id
    - auth_token
    - resource_group_name
    - virtual_machine_name
    - vhd_prefix
    - destination_container_name
    - api_version:
        required: false
        default: '2015-06-15'
    - override_vhds:
        required: false
        default: 'true'
    - auth_type:
        default: "anonymous"
        required: false
    - content_type:
        default: 'application/json'
        required: false
    - proxy_username:
        required: false
    - proxy_password:
        required: false
        sensitive: true
    - proxy_port:
        required: false
        default: "8080"
    - proxy_host:
        required: false
    - trust_all_roots:
        default: "false"
        required: false
    - x_509_hostname_verifier:
        default: "strict"
        required: false
    - trust_keystore:
        required: false
        default: ""
    - trust_password:
        default: ''
        sensitive: true
        required: false
    - keystore:
        required: false
        default: ""
    - keystore_password:
        default: ''
        sensitive: true
        required: false
    - use_cookies:
        default: "true"
        required: false
    - keep_alive:
        default: "true"
        required: false
    - connections_max_per_root:
        default: "50"
        required: false
    - connections_max_total:
        default: "500"
        required: false
    - request_character_set:
        default: "UTF-8"
        required: false

  workflow:
    - save_image_from_vm:
        do:
          http.http_client_post:
            - url: ${'https://management.azure.com/subscriptions/' + subscription_id + '/resourceGroups/' + resource_group_name + '/providers/Microsoft.Compute/virtualMachines/' + virtual_machine_name + '/capture?api-version=' + api_version}
            - headers: "${'Authorization: '+ auth_token}"
            - body: ${'{"vhdPrefix":"' + vhd_prefix + '","destinationContainerName":"' + destination_container_name + '","overwriteVhds":' + override_vhds + '}'}
            - auth_type
            - content_type
            - preemptive_auth
            - proxy_host
            - proxy_port
            - proxy_username
            - proxy_password
            - trust_all_roots
            - x_509_hostname_verifier
            - trust_keystore
            - trust_password
            - keystore
            - keystore_password
            - use_cookies
            - keep_alive
            - connections_max_per_route
            - connections_max_total
        publish:
          - status_code
          - output: ${return_result}
        navigate:
          - SUCCESS: string_equals
          - FAILURE: FAILURE

    - string_equals:
        do:
          strings.string_equals:
            - first_string: "${ status_code }"
            - second_string: "200"
            - ignore_case: "true"
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: FAILURE

  outputs:
    - output
    - status_code

  results:
    - SUCCESS
    - FAILURE
