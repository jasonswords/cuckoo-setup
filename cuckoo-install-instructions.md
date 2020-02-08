# Guide to install Cuckoo on Ubuntu 18.04LTS working as of 21/1/2020

## Install required dependencies
```shell
sudo apt-get install -y python python-pip python-dev libffi-dev libssl-dev libfuzzy-dev libtool flex autoconf libjansson-dev git
```
```shell
sudo apt-get install -y python-virtualenv python-setuptools
```
```shell
sudo apt-get install -y libjpeg-dev zlib1g-dev swig
```

## Install mongodb
```shell
sudo apt-get install -y mongodb
```
## Install postgresql server
```shell
sudo apt-get install -y postgresql libpq-dev
```
## Start postgresql server
```shell
service postgresql@10-main start
```
## Install Virtualbox
#### Add Virtualbox source to Ubuntu sources.list
```shell
echo deb [arch=amd64] https://download.virtualbox.org/virtualbox/debian bionic contrib | sudo tee -a /etc/apt/sources.list.d/virtualbox.list
```
```shell
wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
```

## Update the system to recognise the newly added source
```shell
sudo apt-get update
```
## Install Virtualbox 6.1
```shell
sudo apt-get install virtualbox-6.1 -y
```
## install Volatility
```shell
cd Downloads
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
sudo python setup.py build
sudo python setup.py install
```
## Install distrom3
```shell
cd ../..
sudo -H pip install distorm3
```
## Install yara
```shell
sudo -H pip install yara-python==3.6.3
```
## Install ssdeep
```shell
sudo apt-get install -y ssdeep
ssdeep -V
```
## Install pydeep
```shell
sudo -H pip install pydeep
pip show pydeep
```
## Install openpyxl
```shell
sudo -H pip install openpyxl
```
## Install ujson
```shell
sudo -H pip install ujson
```
## Install jupyter
```shell
sudo -H pip install jupyter
```
## Install tcpdump
```shell
sudo apt-get install tcpdump
sudo apt-get install libcap2-bin
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
```

## If using ubuntu, disable apparmour
```shell
sudo apt-get install -y apparmor-utils
sudo aa-disable /usr/sbin/tcpdump
```
## Install cuckoo sandbox
```shell
pip install -U pip setuptools
sudo -H pip install -U cuckoo
```
## Install net-tools.
```shell
sudo apt install -y net-tools
```
## Run Cuckoo to create default home directory with agent.py script inside it.
```shell
cuckoo
```
## Before the creatio of the VM, a vitural network must be created to provide communications betweem the host and the VM but restrict access the internet.
```shell
vboxmanage hostonlyif create
```

# Create and configure Windows virtual machine now.

### Please name VM "cuckoo1", to follow this guide.

### Install Windows XP or Windows 7.
### Virtualbox guest additions can be anabled to transfer files but remove all traces when finished with it.
### If guest additions are used, enable shared clipboard and drag and drop to make things easier.
## On the Windows VM
### Disable Windows firewall and Windows update.
### Disable UAC also.
### Install python 2.7 for Windows.
### Install all applications needed, older, more vulnerable versions may produce better analysis.
### Configure the VM with applications that are required to test the malware such as vulnerable flash player, adobe reader, browsers and office software.

### Copy the agent.py script on the Ubuntu machine from this path.
```shell
~/.cuckoo/agent/agent.py
```
### To the startup folder on the Windows 7 VM at the following path.
### Open file explorer on Windows VM, select the path text box and paste the following directory path in as is:
```shell
C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup.
```
### Note. Agent.py is only available if you have created the default Cuckoo directories.

## Optional Install.
### Install pillow on Windows 7 VM.
### Pillow is used to take screenshots of what is happening during the process.
### Download get-pip.py script from https://bootstrap.pypa.io
### Right click and save target as get-pip.py
### Save the script as a python script (.py) in c:\python27 directory on the Windows 7 VM.
### Install pip and setuptools for Windows using the following commands.
### Open a command prompt and change directory into c:\python27
```shell
cd c:\python27
python get-pip.py
cd scripts
pip2.7.exe install pillow==3.2

```
## Static IP address
### On Windows 7 VM.
### set static ip.
### IP Address – 192.168.56.101
### Subnet Mask – 255.255.255.0
### Default Gateway – 192.168.56.1
### DNS Servers – 8.8.8.8
###               8.8.4.4


## Snapshot
### Ensure that the VM network interface is set to "Host only adapter" amd the network is "vboxnet0", this must be set before the snapsot is taken.
### Uninstall guest additions and eject the guest additions software from the Windows 7 VM before taking a snapshot, the snapshot must be named "Snapshot1", N.B, this is the default name but with the space removed between "Snapshot" and "1".
### Take the snapshot when the Windows 7 VM is at a booted state, where the desktop is visible.

## Virtualbox setup.
```shell
vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1
vboxmanage modifyvm cuckoo1 --hostonlyadapter1 vboxnet0
vboxmanage modifyvm cuckoo1 --nic1 hostonly
```

## Setup auto restart on vitual interface using systemd service.
```shell
sudo mkdir /opt/systemd/
sudo nano /opt/systemd/vboxhostonly.sh
```
## Copy following text to file.
```shell
#!/bin/bash
vboxmanage hostonlyif create
vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1
```
## Make file executable.
```shell
​sudo chmod a+x /opt/systemd/vboxhostonly.sh
```
## Create file to be run at boot time.
```shell
sudo touch /etc/systemd/system/vboxhostonlynic.service
sudo nano /etc/systemd/system/vboxhostonlynic.service
```
## Copy text to file.
```shell
[Unit]
Description=Setup VirtualBox Hostonly Adapter
After=vboxdrv.service
[Service]
Type=oneshot
ExecStart=/opt/systemd/vboxhostonly.sh
[Install]
WantedBy=multi-user.target
```
## Reload service and set service to run automatically at boot.
```shell
sudo systemctl daemon-reload
sudo systemctl enable vboxhostonlynic.service
```
## Implement IP forwarding from the host to guest VM.
```shell
sudo iptables -A FORWARD -o eth0 -i vboxnet0 -s 192.168.56.0/24 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -L
```
## Next, enable IP forwarding in the kernel so that these settings are set to Active (required for WWW Internet access).
```shell
echo 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward
sudo sysctl -w net.ipv4.ip_forward=1
```
## Make iptables persistent at reboots.
```shell
sudo apt-get install -y iptables-persistent
sudo nano /etc/sysctl.conf
```
### Remove "#" from in front of net.ipv4.ip_forward=1.

## Start mongodb service.
```shell
service mongodb start
```


## Configure Cuckoo configuration files (.conf files).
```shell
cd ~/.cuckoo/conf
sudo nano cuckoo.conf
```
	[cuckoo]
	memory_dump = yes
	machinery = virtualbox

	[resultserver]
	ip = 192.168.56.1

```shell
sudo nano virtualbox.conf
```
	[virtualbox]
	mode = gui
	machines = cuckoo1

	[cuckoo1]
	label = cuckoo1
	platform = windows
	ip = 192.168.56.101
	snapshot = Snapshot1
```shell
sudo nano processing.conf
```
	[memory]
	enabled = yes

	[virustotal]
	enabled = yes
```shell
sudo nano memory.conf
```
	[basic]
	guest_profile = “Win7SP1x64”

## Make sure to select the correct version for Volatility.
## For a list of other Volatility guest profiles.
```shell
vol.py --info |grep Profiles -A48
```
```shell
sudo nano reporting.conf
```
	[singlefile]
	# Enable creation of report.html?
	enabled = yes
    
	[mongodb]
	enabled = yes



## Another method of reporting is MAEC, more information [here](https://maecproject.github.io/documentation/overview/).
To enable MAEC reporting in cuckoo.
--
Open this file for editing:
```shell
sudo nano /usr/local/lib/python2.7/dist-packages/cuckoo/common/config.py
```
If using nano, ctl + w to search the file, type in "reporting".
--
Add additional entry to the dictionary:
```shell
"maecreport" : { 
                "enabled": Boolean(False)
            },
```
As seen in this image
![alt text] (https://github.com/jasonswords/cuckoo-setup/blob/master/maec.png, "Image to show dictionary")
In the .cuckoo/conf/reporting.conf file, add an additional entry for MAEC
```shell
sudo nano /home/$USER/.cuckoo/conf/reporting.conf
```
Add an additional entry in this file.
```shell
[maecreport]
enabled = yes
```
The final step is to copy the required files from [github](https://github.com/MAECProject/cuckoo/tree/maec5.0-cuckoo2.0/cuckoo/reporting).
Two file are needed, maec_api_call_mappings.json and maecreport.py
These two files can be saved (click RAW, then right click, save as) and copied into:
```shell
/usr/local/lib/python2.7/dist-packages/cuckoo/reporting
```
Sudo privileges will be required.
The system should be rebooted to ensure changes take effect..

#
#

## Update signatures
```shell
cuckoo community 
```
## Run cuckoo
```shell
cuckoo
```

## In another terminal run web server.
```shell
cuckoo web runserver
```
### If Error: That port is already in use is desplayed, kill any sevice using that port number.
```shell
sudo fuser -k 8000/tcp
```

### Visit localhost:8000 to reach the Cuckoo interface.
