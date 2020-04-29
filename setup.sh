# Trusty (14.04 LTS) and older
VER=trusty
echo "deb http://llvm.org/apt/$VER/ llvm-toolchain-$VER-3.7 main
deb-src http://llvm.org/apt/$VER/ llvm-toolchain-$VER-3.7 main" | \
  sudo tee /etc/apt/sources.list.d/llvm.list
wget -O - http://llvm.org/apt/llvm-snapshot.gpg.key | sudo apt-key add -
sudo apt-get update

# For Bionic (18.04 LTS)
# sudo apt-get -y install bison build-essential cmake flex git libedit-dev \
#   libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev

# For Eon (19.10)
# sudo apt install -y bison build-essential cmake flex git libedit-dev \
#   libllvm7 llvm-7-dev libclang-7-dev python zlib1g-dev libelf-dev

# For other versions
sudo apt-get -y install bison build-essential cmake flex git libedit-dev \
  libllvm3.7 llvm-3.7-dev libclang-3.7-dev python zlib1g-dev libelf-dev

# For Lua support
# sudo apt-get -y install luajit luajit-5.1-dev
