FROM node:18

# Install Rust and Cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install Scarb with PATH setup
ENV PATH="/root/.local/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh

# Install starknet-devnet using cargo
RUN cargo install starknet-devnet

WORKDIR /app

COPY package*.json ./
COPY ./.env ./.env
COPY ./.env.example ./.env.example
RUN yarn install

COPY . .

# Default command starts devnet
CMD ["starknet-devnet", "--seed", "0", "--account-class", "cairo1", "--host", "0.0.0.0", "--port", "5050"]
