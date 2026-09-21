FROM h7ctf26/evm-harness:latest
COPY foundry.toml /project/foundry.toml
COPY src /project/src
RUN forge build && forge inspect src/Setup.sol:Setup bytecode > /setup.bytecode
ENV CHALL=genesis SETUP_VALUE=0
