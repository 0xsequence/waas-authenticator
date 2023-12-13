# waas-authenticator

## Development setup

1. Generate an RSA keypair:

```
ssh-keygen -t rsa -f ./etc/id_rsa
```

2. Copy the sample config file:

```
cp ./etc/waas-auth.sample.conf ./etc/waas-auth.conf
```

3. Edit `./etc/waas-auth.conf` and replace `YOUR-PUBLIC-KEY-HERE` with the contents of `./etc/id_rsa.pub`.
4. Run the following to start the required services:

```
docker-compose up
```

