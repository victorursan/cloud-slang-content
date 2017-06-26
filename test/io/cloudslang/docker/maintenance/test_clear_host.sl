#   (c) Copyright 2014-2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################

namespace: io.cloudslang.docker.maintenance

imports:
  maintenance: io.cloudslang.docker.maintenance
  images: io.cloudslang.docker.images

flow:
  name: test_clear_host

  inputs:
    - host
    - port:
        required: false
    - username
    - password
    - image_name_to_pull
    - image_name_to_run

  workflow:
    - pre_test_cleanup:
        do:
          maintenance.clear_host:
            - docker_host: ${ host }
            - port
            - docker_username: ${ username }
            - docker_password: ${ password }
        navigate:
          - SUCCESS: test_verify_no_images
          - FAILURE: MACHINE_IS_NOT_CLEAN

    - test_verify_no_images:
        do:
          images.test_verify_no_images:
            - host
            - port
            - username
            - password
        navigate:
          - SUCCESS: pull_image
          - FAILURE: MACHINE_IS_NOT_CLEAN
          - FAIL_VALIDATE_SSH: MACHINE_IS_NOT_CLEAN
          - FAIL_GET_ALL_IMAGES_BEFORE: FAIL_GET_ALL_IMAGES_BEFORE

    - pull_image:
        do:
          images.pull_image:
            - host
            - port
            - username
            - password
            - image_name: ${ image_name_to_pull }
        navigate:
          - SUCCESS: clear_docker_host
          - FAILURE: FAIL_PULL_IMAGE

    - clear_docker_host:
        do:
          maintenance.clear_host:
            - docker_host: ${ host }
            - port
            - docker_username: ${ username }
            - docker_password: ${ password }
        navigate:
          - SUCCESS: test_verify_no_images_post_cleanup
          - FAILURE: MACHINE_IS_NOT_CLEAN

    - test_verify_no_images_post_cleanup:
        do:
          images.test_verify_no_images:
            - host
            - port
            - username
            - password
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: MACHINE_IS_NOT_CLEAN
          - FAIL_VALIDATE_SSH: MACHINE_IS_NOT_CLEAN
          - FAIL_GET_ALL_IMAGES_BEFORE: FAIL_GET_ALL_IMAGES_BEFORE

  results:
    - SUCCESS
    - FAIL_GET_ALL_IMAGES_BEFORE
    - MACHINE_IS_NOT_CLEAN
    - FAIL_PULL_IMAGE
