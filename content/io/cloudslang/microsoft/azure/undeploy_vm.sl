#   (c) Copyright 2016 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
#!!
#! @description: VM deprovision flow.
#!
#! @input subscription_id: The ID of the Azure Subscription on which the VM should be created.
#! @input resource_group_name: The name of the Azure Resource Group that should be used to create the VM.
#! @input username: The username to be used to authenticate to the Azure Management Service.
#! @input password: The password to be used to authenticate to the Azure Management Service.
#! @input login_authority: optional - URL of the login authority that should be used when retrieving the Authentication Token.
#!                         Default: 'https://sts.windows.net/common'
#! @input vm_name: The name of the virtual machine to be created.
#!                 Virtual machine name cannot contain non-ASCII or special characters.
#! @input public_ip_address_name: Name of the public address to be created
#! @input virtual_network_name: The name of the virtual network to which the created VM should be attached.
#! @input availability_set_name: Specifies information about the availability set that the virtual machine
#!                               should be assigned to. Virtual machines specified in the same availability set
#!                               are allocated to different nodes to maximize availability.
#! @input storage_account: The name of the storage account in which the OS and Storage disks of the VM should be created.
#! @input container_name: The name of the container that contains the storage blob to be deleted.
#!                        Default: 'vhds'
#! @input nic_name: Name of the network interface card
#! @input connect_timeout: optional - time in seconds to wait for a connection to be established
#!                         Default: '0' (infinite)
#! @input socket_timeout: optional - time in seconds to wait for data to be retrieved
#!                        Default: '0' (infinite)
#! @input proxy_host: optional - proxy server used to access the web site
#! @input proxy_port: optional - proxy server port - Default: '8080'
#! @input proxy_username: optional - username used when connecting to the proxy
#! @input proxy_password: optional - proxy server password associated with the <proxy_username> input value
#! @input trust_all_roots: optional - specifies whether to enable weak security over SSL - Default: false
#! @input x_509_hostname_verifier: optional - specifies the way the server hostname must match a domain name in
#!                                 the subject's Common Name (CN) or subjectAltName field of the X.509 certificate
#!                                 Valid: 'strict', 'browser_compatible', 'allow_all' - Default: 'allow_all'
#!                                 Default: 'strict'
#! @input trust_keystore: optional - the pathname of the Java TrustStore file. This contains certificates from
#!                        other parties that you expect to communicate with, or from Certificate Authorities that
#!                        you trust to identify other parties.  If the protocol (specified by the 'url') is not
#!                        'https' or if trust_all_roots is 'true' this input is ignored.
#!                        Default value: ..JAVA_HOME/java/lib/security/cacerts
#!                        Format: Java KeyStore (JKS)
#! @input trust_password: optional - the password associated with the Trusttore file. If trust_all_roots is false
#!                        and trust_keystore is empty, trust_password default will be supplied.
#!
#! @output output: Information about the virtual machine that has been deprovisioned
#! @output status_code: 200 if request completed successfully, others in case something went wrong
#! @output return_code: 0 if success, -1 if failure
#! @output error_message: If there is any error while running the flow, it will be populated, empty otherwise
#!
#! @result SUCCESS: The flow completed successfully.
#! @result FAILURE: Something went wrong
#!!#
########################################################################################################################

namespace: io.cloudslang.microsoft.azure

imports:
  json: io.cloudslang.base.json
  strings: io.cloudslang.base.strings
  flow: io.cloudslang.base.utils
  auth: io.cloudslang.microsoft.azure.utility
  vm: io.cloudslang.microsoft.azure.compute.virtual_machines
  ip: io.cloudslang.microsoft.azure.compute.network.public_ip_addresses
  nic: io.cloudslang.microsoft.azure.compute.network.network_interface_card
  storage: io.cloudslang.microsoft.azure.compute.storage.containers
  auth_storage: io.cloudslang.microsoft.azure.compute.storage

flow:
  name: undeploy_vm

  inputs:
    - subscription_id
    - resource_group_name
    - username
    - login_authority:
        default: 'https://sts.windows.net/common'
        required: false
    - vm_name
    - container_name:
        default: 'vhds'
        required: false
    - storage_account
    - password:
        sensitive: true
    - connect_timeout:
        default: "0"
        required: false
    - proxy_host:
        required: false
    - proxy_port:
        required: false
    - proxy_username:
        required: false
    - proxy_password:
        required: false
        sensitive: true
    - trust_all_roots:
        required: false
        default: 'false'
    - x_509_hostname_verifier:
        required: false
        default: 'strict'
    - trust_keystore:
        required: false
    - trust_password:
        required: false
        sensitive: true

  workflow:
    - get_auth_token:
        do:
          auth.get_auth_token:
            - username
            - password
            - proxy_host
            - proxy_port
            - proxy_username
            - proxy_password
            - trust_all_roots
            - x_509_hostname_verifier
            - trust_keystore
            - trust_password
        publish:
          - auth_token
          - return_code
          - error_message: ${exception}
        navigate:
          - SUCCESS: stop_vm
          - FAILURE: on_failure

    - stop_vm:
        do:
          vm.stop_vm:
            - subscription_id
            - resource_group_name
            - auth_token
            - vm_name
            - connect_timeout
            - socket_timeout: '0'
            - proxy_host
            - proxy_port
            - proxy_username
            - proxy_password
            - x_509_hostname_verifier
            - trust_all_roots
            - trust_keystore
            - trust_password
        publish:
          - status_code
          - error_message
        navigate:
          - SUCCESS: delete_vm
          - FAILURE: on_failure

    - delete_vm:
        do:
          vm.delete_vm:
            - subscription_id
            - resource_group_name
            - auth_token
            - vm_name
            - connect_timeout
            - socket_timeout: '0'
            - proxy_host
            - proxy_port
            - proxy_username
            - proxy_password
            - trust_all_roots
            - x_509_hostname_verifier
            - trust_keystore
            - trust_password
        publish:
          - status_code
          - error_message
        navigate:
          - SUCCESS: list_vms_in_a_resource_group
          - FAILURE: on_failure

    - list_vms_in_a_resource_group:
        do:
          vm.list_vms_in_a_resource_group:
            - subscription_id
            - resource_group_name
            - auth_token
            - connect_timeout
            - socket_timeout: '0'
            - proxy_host
            - proxy_port
            - proxy_username
            - proxy_password
            - trust_all_roots
            - x_509_hostname_verifier
            - trust_keystore
            - trust_password
        publish:
          - deleted_vm: ${output}
          - status_code
          - error_message
        navigate:
          - SUCCESS: retrieve_vm
          - FAILURE: on_failure

    - retrieve_vm:
        do:
          json.json_path_query:
            - json_object: ${deleted_vm}
            - json_path: 'value.*.name'
        publish:
          - return_deleted: ${return_result}
        navigate:
          - SUCCESS: check_empty_vm
          - FAILURE: on_failure

    - check_empty_vm:
        do:
          strings.string_occurrence_counter:
            - string_in_which_to_search: ${return_deleted}
            - string_to_find: ${vm_name}
        navigate:
          - SUCCESS: wait_vm_check
          - FAILURE: delete_nic

    - wait_vm_check:
        do:
          flow.sleep:
            - seconds: '20'
        navigate:
          - SUCCESS: list_vms_in_a_resource_group
          - FAILURE: on_failure

    - delete_nic:
        do:
          nic.delete_nic:
            - subscription_id
            - resource_group_name
            - auth_token
            - nic_name: ${vm_name + '-nic'}
            - connect_timeout
            - socket_timeout: '0'
            - proxy_host
            - proxy_port
            - proxy_username
            - proxy_password
            - trust_all_roots
            - x_509_hostname_verifier
            - trust_keystore
            - trust_password
        publish:
          - status_code
          - error_message
        navigate:
          - SUCCESS: list_nics_within_resource_group
          - FAILURE: on_failure

    - list_nics_within_resource_group:
        do:
          nic.list_nics_within_resource_group:
            - subscription_id
            - resource_group_name
            - auth_token
            - connect_timeout
            - socket_timeout: '0'
            - proxy_host
            - proxy_port
            - proxy_username
            - proxy_password
            - trust_all_roots
            - x_509_hostname_verifier
            - trust_keystore
            - trust_password
        publish:
          - status_code
          - error_message
          - nics: ${output}
        navigate:
          - SUCCESS: retrieve_nics
          - FAILURE: on_failure

    - retrieve_nics:
        do:
          json.json_path_query:
            - json_object: ${nics}
            - json_path: 'value.*.name'
        publish:
          - nics_result: ${return_result}
        navigate:
          - SUCCESS: check_empty_nic
          - FAILURE: on_failure

    - check_empty_nic:
        do:
          strings.string_occurrence_counter:
            - string_in_which_to_search: ${nics_result}
            - string_to_find: ${vm_name + '-nic'}
        navigate:
          - SUCCESS: wait_nic_check
          - FAILURE: delete_public_ip_address

    - wait_nic_check:
        do:
          flow.sleep:
            - seconds: '20'
        navigate:
          - SUCCESS: list_nics_within_resource_group
          - FAILURE: on_failure

    - delete_public_ip_address:
        do:
          ip.delete_public_ip_address:
            - subscription_id
            - resource_group_name
            - auth_token
            - public_ip_address_name: ${vm_name + '-ip'}
            - connect_timeout
            - socket_timeout: '0'
            - proxy_host
            - proxy_port
            - proxy_username
            - proxy_password
            - trust_all_roots
            - x_509_hostname_verifier
            - trust_keystore
            - trust_password
        publish:
          - status_code
          - error_message
        navigate:
          - SUCCESS: list_public_ip_addresses_within_resource_group
          - FAILURE: on_failure

    - list_public_ip_addresses_within_resource_group:
        do:
          ip.list_public_ip_addresses_within_resource_group:
            - subscription_id
            - resource_group_name
            - auth_token
            - connect_timeout
            - socket_timeout: '0'
            - proxy_host
            - proxy_port
            - proxy_username
            - proxy_password
            - trust_all_roots
            - x_509_hostname_verifier
            - trust_keystore
            - trust_password
        publish:
          - status_code
          - error_message
          - ips_result: ${output}
        navigate:
          - SUCCESS: retrieve_ips
          - FAILURE: on_failure

    - retrieve_ips:
        do:
          json.json_path_query:
            - json_object: ${ips_result}
            - json_path: 'value.*.name'
        publish:
          - ips_response: ${return_result}
        navigate:
          - SUCCESS: check_empty_ip
          - FAILURE: on_failure

    - check_empty_ip:
        do:
          strings.string_occurrence_counter:
            - string_in_which_to_search: ${ips_response}
            - string_to_find: ${vm_name + '-ip'}
        navigate:
          - SUCCESS: wait_ip_check
          - FAILURE: get_storage_auth

    - wait_ip_check:
        do:
          flow.sleep:
            - seconds: '20'
        navigate:
          - SUCCESS: list_public_ip_addresses_within_resource_group
          - FAILURE: on_failure

    - get_storage_auth:
        do:
          auth_storage.get_storage_account_keys:
            - subscription_id
            - resource_group_name
            - auth_token
            - storage_account
            - connect_timeout
            - socket_timeout: '0'
            - proxy_host
            - proxy_port
            - proxy_username
            - proxy_password
            - trust_all_roots
            - x_509_hostname_verifier
            - trust_keystore
            - trust_password
        publish:
          - key
          - status_code
          - error_message
        navigate:
          - SUCCESS: delete_osdisk
          - FAILURE: on_failure

    - delete_osdisk:
        do:
          storage.delete_blob:
            - storage_account
            - key: ${key}
            - container_name
            - blob_name: ${vm_name + 'osDisk.vhd'}
            - proxy_host
            - proxy_port
            - proxy_username
            - proxy_password
        publish:
          - status_code
        navigate:
          - SUCCESS: get_deleted_blob
          - FAILURE: on_failure

    - get_deleted_blob:
        do:
          storage.delete_blob:
            - storage_account
            - key
            - container_name
            - blob_name: ${vm_name + 'storageDisk.vhd'}
            - proxy_host
            - proxy_port
            - proxy_username
            - proxy_password
        publish:
          - status_code
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: FAILURE

  outputs:
    - return_code
    - status_code
    - error_message

  results:
    - SUCCESS
    - FAILURE
extensions:
  graph:
    steps:
      check_empty_vm:
        x: 905
        y: 311
      list_public_ip_addresses_within_resource_group:
        x: 1536
        y: 521
      list_vms_in_a_resource_group:
        x: 693
        y: 102
      wait_nic_check:
        x: 1328
        y: 311
      retrieve_ips:
        x: 1536
        y: 731
      wait_vm_check:
        x: 695
        y: 309
      get_auth_token:
        x: 67
        y: 104
      delete_vm:
        x: 485
        y: 99
      get_deleted_blob:
        x: 700
        y: 519
        navigate:
          c4b4581a-5e24-3410-5487-22137f556ae0:
            targetId: c00e7719-f536-c71a-e984-1d2b65f093f2
            port: SUCCESS
          62237d04-a245-85d4-18cf-2b55b5e16975:
            targetId: 0547dcd4-dd53-1ceb-bb98-8e7ca07908bd
            port: FAILURE
      retrieve_nics:
        x: 1325
        y: 100
      list_nics_within_resource_group:
        x: 1113
        y: 99
      check_empty_ip:
        x: 1326
        y: 733
      stop_vm:
        x: 277
        y: 102
      delete_nic:
        x: 1122
        y: 311
      delete_osdisk:
        x: 906
        y: 524
      get_storage_auth:
        x: 1119
        y: 522
      retrieve_vm:
        x: 911
        y: 98
      wait_ip_check:
        x: 1328
        y: 524
      delete_public_ip_address:
        x: 1536
        y: 310
      check_empty_nic:
        x: 1532
        y: 104
    results:
      SUCCESS:
        c00e7719-f536-c71a-e984-1d2b65f093f2:
          x: 487
          y: 523
      FAILURE:
        0547dcd4-dd53-1ceb-bb98-8e7ca07908bd:
          x: 698
          y: 737