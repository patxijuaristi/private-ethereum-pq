Modified GO-Ethereum Private Network 💻
================================================================

Modified version of the Go-Ethereum library to enable the use of other post-quantum algorithms in the future.

The network is launched using Docker and is composed of the following containers:

 - **Bootnode** (*geth-pq-bootnode*): The node that starts the peer discovery. It listens on port 30303 and the rest of the nodes join the network by connecting to this bootnode first.
 - **JSON-RPC endpoint** (*geth-pq-rpc-endpoint*): This node exposes the JSON-RPC API over HTTP on port 8545. It has been published that port of the Docker container on the host machine to allow external interaction with the private blockchain.
 - **Miner** (*geth-pq-miner*): The node that will be mining to create new blocks on the blockchain. Each time a new block is created, the established account will get its reward.

To create the bootnode key, the next command must be executed:

 ```
bootnode -genkey bootnode.key
```

Once we have the key, we have to execute the next command including the generated key.

```
bootnode -nodekeyhex xxxxxxxxxxxxxxxxxxx -writeaddress
```

Then just build the images and run:

```
docker-compose build
```

```
docker-compose up
```