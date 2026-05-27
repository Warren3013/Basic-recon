# Basic-recon
Recon with existing tools in rust for faster execution

# Tools
subfinder
assetfinder
httprobe
nuclei
rustscan

# Requirement
Install above tools with the below commands:
sudo apt install subfinder
sudo apt install assetfinder
sudo apt install httprobe
sudo apt install nuclei
wget https://github.com/bee-san/RustScan/releases/download/2.4.1/rustscan.deb.zip | unzip rustscan.deb.zip | sudo dpkg -i rustscan.deb
sudo apt install nmap
sudo apt install cargo

# Installation
git clone https://github.com/Warren3013/Basic-recon/tree/main/recon.rs && cd Basic-recon && rustc recon.rs -o recon
