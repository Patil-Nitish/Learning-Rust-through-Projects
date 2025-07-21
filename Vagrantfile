Vagrant.configure("2") do |config|
  # Use Ubuntu 22.04 LTS (Jammy)
  config.vm.box = "ubuntu/jammy64"

  # Prevent symlink creation issues on Windows hosts
  config.vm.synced_folder ".", "/vagrant",
    type: "virtualbox",
    SharedFoldersEnableSymlinksCreate: false

  # Bridge to your physical network interface (edit if needed)
  config.vm.network "public_network",
    bridge: "Intel(R) Wi-Fi 6 AX203",
    auto_config: true

  # VM hardware configuration
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
    vb.name = "RustNetworking-VM"
  end

  # Shell provisioning: install Rust, networking tools, etc.
  config.vm.provision "shell", inline: <<-SHELL
    sudo apt-get update -y
    sudo apt-get install -y libpcap-dev tcpdump wireguard curl build-essential

    # Install Rust without user prompt
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

    # Add Rust to PATH
    echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
    source $HOME/.cargo/env

    # Optional Rust tools (for development)
    ~/.cargo/bin/rustup component add clippy rustfmt
  SHELL
end
