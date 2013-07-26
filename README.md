# itsdangerous-php

A PHP port of itsdangerous by @mitsuhiko

## Differences from itsdangerous

1. `Signer`s cannot be specified in the constructor of a `Serializer`.
2. `salt` cannot be specified in the methods of a `Serializer`. You should create new instances of the `Serializer` instead.

