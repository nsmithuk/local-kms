
If you have an older version of openssl locally, all key typed can be generated within a container.

For example
```bash
docker run -it --rm -v="${PWD}:/script" -w /script --entrypoint="" alpine/openssl sh
```

Install bash and uuidgen
```
apk update && apk add --no-cache bash uuidgen
```

Run script
```bash
./keygen.sh ML_DSA_44
```
