# cuckoo-setup
This repository contains  files used to visualise Cuckoo json report files. Using multiple libraries, a network graph containing process, sub-process, file interactions and registry interactions. Network interactions will come later. The repository also contains files to intergrate the application directly into Cukoo sandbox and provide an overview of the malware porcesses and files activity. 

This is an alteration of a previously created graphing library created at "https://github.com/keithjjones/visualize_logs" by Keith J Jones which was originally intended for Cuckoo modified, a fork of Cuckoo. 

If you notice any inaccuracies, please feel free to notify or rectify the inaccuracy yourself. Hope it helps!!


In preparation of implementing this application, several important stages must be completed so Cuckoo can execute the scripts prepared. With Cuckoo already installed and running, minimal additional packages are required for the graph visualisation. As the visualisation application requires Python3, install Python3 package manager PIP3 and install GraphViz, an open source graph visualisation software. Both can be installed by chaining commands together.
```shell
$ sudo apt-get install python3-pip graphviz
```
Python packages can be installed in one of two ways. Method 2, use the command line to type each package out or chain multiple packages together similar to the previous command or method 2, clone the repository and use the requirements.txt file to list the packages to PIP3. 
Method 1:
```shell
$ pip3 install networkx pandas plotly setuptools pydot pyparsing graphviz pydotplus
```
Method 2:
Download the files from GitHub or use git command line to clone the repository to the current working directory. To clone the repository:
```shell
$ git clone repository/name
```
Then move into the downloaded directory.
```shell
$ cd visualize_json_report
```
Using PIP3, install all the dependencies.
```shell
$ pip3 install -r requirements.txt
```
This command will read the contents of the requirements file and install each package, one by one. 
After all dependencies have installed, some additional configurations are required to Cuckoo setup files to integrate the application. The first objective is to copy the downloaded directory to the Cuckoo working directory.  Assuming the directory was downloaded to the download’s directory.
```shell
$ cp $HOME/Downloads/visualize_json_report/ $HOME/.cuckoo/
```

After copying the directory to the Cuckoo home directory, the ownership of the file must be changed so the current user can access the files. 
```shell
$ sudo chown $USER $HOME/.cuckoo/visualize_json_report/*
```
With the ownership of the files are changed, a file must be copied to the Cuckoo system reporting directory. This move required elevated privileges to move the file.
```shell
$ sudo cp $HOME/.cuckoo/visualize_json_report/visualize_json_report.py /usr/local/lib/python2.7/dist-packages/cuckoo/reporting/
```

This command copies the module from the downloaded directory into the reporting directory of Cuckoo. The module inherits from the super class report and also inherits additional class variable such as the path to where the json report is stored. This will be used to specify the json report file when visualising the data. The module uses class variables and additional data to make available additional options to the user when running the system. These options allow the user to specify the type of data to be visualized when running Cuckoo. This is controlled from the reporting.conf file. The remaining code creates a list of variables and executes the command base on the option passed from the config file.
The module is broken into two sections. The first section accumulates the data needed to execute the visualisation application.
 
In the image, there are a number of variables. Home_path variable returns the home path and is used with the OS module to join with the path to the visualize_json_report directory. Report_path is an inherited class variable returning the path to the latest json report file created. Choice variable is a variable created to make changing the graph output easier through the config file. The parameters list is created and later populated with parameters for executing the application. 
The next image contains the logic of the module. This simply checks the configuration choice and executes the graph application using those parameters. As displayed in the next image, it can be clearly seen various choices of parameters, including creating the graph in the same directory as the json report file naming the file report.html. There are four configuration choices:
1)	Visualize processes only
2)	Visualize processes and network data
3)	Visualize processes and file data
4)	Visualize process and registry data
5)	Visualize process data only. This is the default for configuration issues. 
Finally, after the correct statement populates the parameters list, the subprocess module executes the commands on the system. This module allows Python to execute system processes. As this is a Python 2 application (Cuckoo) executing a Python 3 application (Visualize_json_report), the Python 3 interpreter must be called specifically.
 

With the module completed, an entry into the Cuckoo system configuration file must be added so Cuckoo recognises the module. To open the configuration using Nano terminal editor:
```shell
$ sudo nano /usr/local/lib/python2.7/dist-packages/cuckoo/common/config.py
```
To find the specific location to insert into the configuration file use keyboard shortcut CTL + W, then type “reporting” into the terminal to locate the reporting dictionary containing all the reporting modules. Insert an additional entry for the module as follows:

"visualize_json_report" : {
  "enabled" : Boolean(True)
  "report_type" : Int(1)
},
 
As displayed in the image, a dictionary value is inserted with the naming of the module file inserted previously. Two variables are also created. The “enabled” variable permits the user to easily activate and deactivate the module when required. The “report_type” variable was created to allow the user to change the graph output using the configuration file in the Cuckoo home directory. 
The last stage to activate the module is to add an entry into the configuration file which is stored in the Cuckoo home directory. This entry allows the user to control the module easily, enabling or disabling, and choosing what display they would like used. To create this entry, open the reporting.conf configuration file using Nano terminal editor.
```shell
$ nano $HOME/.cuckoo/conf/reporting.conf
```
Inside this file, create an entry as follows.

[visualize_json_report]
enabled = on
report_type = 1
 
As previously, the “[visualize_json_report]” specifies the module itself, while the two parameters relate to the variables specified in the other system configuration file. The “enabled” parameter allows the user to disable or enable the module while the “report_type” variable allows the user to change the graph output data type. 
The process is now complete. Running Cuckoo should now recognise the module and create a graph after the analysis completes. Changing the report type variable value requires a restart of the Cuckoo main process recognise changes. 
The graph application will automatically create an additional tab when execution completes. Although simple processes can be graph quite fast, but graphing additional data, such as processes and file data, can take extended periods of time, allowing for file parsing and processing. Graphing file data and processes can take 2 – 3 minutes to complete all pre-processing and graph creation. 

