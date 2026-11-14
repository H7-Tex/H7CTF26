FROM h7ctf26/evm-harness:latest
COPY foundry.toml /project/foundry.toml
COPY src /project/src
RUN forge build && forge inspect src/Setup.sol:Setup bytecode > /setup.bytecode
ENV CHALL=mirror_pool SETUP_VALUE=10000000000000000000
