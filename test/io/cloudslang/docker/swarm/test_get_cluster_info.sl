#   (c) Copyright 2014-2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################

namespace: io.cloudslang.docker.swarm

imports:
  swarm: io.cloudslang.docker.swarm
  strings: io.cloudslang.base.strings

flow:
  name: test_get_cluster_info

  inputs:
    - swarm_manager_ip
    - swarm_manager_port
    - number_of_agent_containers_in_cluster
    - host
    - port:
        required: false
    - username
    - password:
        required: false
    - private_key_file:
        required: false
    - timeout:
        required: false
    - agent_ip_addresses
    - attempts:
        required: false
    - time_to_sleep:
        required: false

  workflow:
    - setup_cluster:
        do:
          swarm.create_cluster_with_nodes:
            - manager_machine_ip: ${swarm_manager_ip}
            - manager_machine_username: ${username}
            - manager_machine_password: ${password}
            - manager_machine_private_key_file: ${private_key_file}
            - manager_machine_port: ${swarm_manager_port}
            - agent_ip_addresses
            - agent_usernames: ${username + "," + username}
            - agent_passwords: ${get(password,"") + "," + get(password,"")}
            - agent_private_key_files: ${private_key_file + "," + private_key_file}
            - attempts
            - time_to_sleep
        navigate:
          - SUCCESS: get_cluster_info
          - CREATE_SWARM_CLUSTER_PROBLEM: SETUP_CLUSTER_PROBLEM
          - PRE_CLEAR_MANAGER_MACHINE_PROBLEM: SETUP_CLUSTER_PROBLEM
          - PRE_CLEAR_AGENT_MACHINES_PROBLEM: SETUP_CLUSTER_PROBLEM
          - START_MANAGER_CONTAINER_PROBLEM: SETUP_CLUSTER_PROBLEM
          - ADD_NODES_TO_THE_CLUSTER_PROBLEM: SETUP_CLUSTER_PROBLEM
          - GET_NUMBER_OF_NODES_IN_CLUSTER_PROBLEM: SETUP_CLUSTER_PROBLEM
          - NODES_NOT_ADDED: SETUP_CLUSTER_PROBLEM

    - get_cluster_info:
        do:
          swarm.get_cluster_info:
            - swarm_manager_ip
            - swarm_manager_port
            - host
            - port
            - username
            - password
            - private_key_file
            - timeout
        publish:
          - number_of_containers_in_cluster

    - verify_number_of_containers_in_cluster:
        do:
          strings.string_equals:
            - first_string: ${str(number_of_agent_containers_in_cluster)}
            - second_string: ${number_of_containers_in_cluster}
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: VERIFY_NUMBER_OF_CONTAINERS_IN_CLUSTER_PROBLEM
  results:
    - SUCCESS
    - SETUP_CLUSTER_PROBLEM
    - FAILURE
    - VERIFY_NUMBER_OF_CONTAINERS_IN_CLUSTER_PROBLEM
