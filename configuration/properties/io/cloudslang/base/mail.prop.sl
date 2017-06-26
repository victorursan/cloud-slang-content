#   (c) Copyright 2014-2017 Hewlett-Packard Enterprise Development Company, L.P.
#   All rights reserved. This program and the accompanying materials
#   are made available under the terms of the Apache License v2.0 which accompany this distribution.
#
#   The Apache License is available at
#   http://www.apache.org/licenses/LICENSE-2.0
#
########################################################################################################################
# Sample system property file for email protocol
#
# io.cloudslang.base.hostname: Host name.
#                              Example: 'smtp.example.com'
# io.cloudslang.base.port: Email server port.
# io.cloudslang.base.from: Sender email.
# io.cloudslang.base.to: Receiver email.
# io.cloudslang.base.username: Sender username.
# io.cloudslang.base.password: Sender password.
#
########################################################################################################################

namespace: io.cloudslang.base

properties:
  - hostname: 'localhost'
  - port:
      value: "49154"
  - from: 'user@example.com'
  - to: 'otheruser@example.com'
  - username: 'user'
  - password:
      value: 'pwd'
      sensitive: true
