# BCHD regtest harness

This setup allows for additional tests into bchd's continuous integration pipeline using regtest.  Docker compose is used to setup a regtest network with two bchd instances connected.

## Run Tests

Run the tests against the regtest network using:

```
$ ./test.sh
```

When done run `docker-compose down` to remove the regtest network.

## Debugging with VSCode

An example `launch.json` file has been included for debugging with vscode.  Copy this config into the `.vscode/launch.json` file created by VSCode.
