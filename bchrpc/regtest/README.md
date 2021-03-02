# BCHD rpc regtest network

This regtest setup allows for integrating additional tests into bchd's continuous integration pipeline.

## Running Tests

```
$ cd ./bchrpc/regtest
$ docker-compose up -d
$ npm i
$ npm test
```
