# Basic-recon
Recon with existing tools in rust for faster execution

# Tools
subfinder, assetfinder, httprobe, nuclei, rustscan, feroxbuster

# Requirement
Install above tools with the below commands:
<ul>sudo apt install subfinder</ul>
<ul>sudo apt install assetfinder</ul>
<ul>sudo apt install httprobe</ul>
<ul>sudo apt install nuclei</ul>
<ul>wget https://github.com/bee-san/RustScan/releases/download/2.4.1/rustscan.deb.zip | unzip rustscan.deb.zip | sudo dpkg -i rustscan.deb</ul>
<ul>sudo apt install nmap</ul>
<ul>sudo apt install cargo</ul>
<ul>sudo apt install feroxbuster</ul>

# Installation

git clone https://github.com/Warren3013/Basic-recon.git && cd Basic-recon && rustc recon.rs -o recon

# Usage

./recon <domain>
