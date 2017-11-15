## README


CONTENTS OF THIS FILE
---------------------
```
 * Introduction
 * Requirements
 * Recommended modules
 * Installation
 * Includes
 * Command line arguments
 * Configuration
 * Troubleshooting
 * FAQ
 * Maintainers
```
 
INTRODUCTION 
------------
```
atdsubmitter.py is the python script which will run as a daemon process at user Linux device.
Using 'configure' option of a daemon user can configure the system for bro extracted sample submission.
Configuration will be saved to the file and then user can start the daemon with stored configuration which need only password to be provided.
Using username and password daemon will login and start the REST submission for extracted files.
```

REQUIREMENTS 
------------
	- Linux system with recommended python modules for Python > 2.7 Version.
	- Device should have sufficient space to save the logs. (Partition where script resides)
	- Sufficient memory and CPU's for execution and for better performance.
	- Write permission to the script to create logs / configuration.


RECOMMENDED MODULES
-------------------
Device should have below modules pre-installed to work properly,
```
Python modules list :
pip
sys
os
time
atexit
magic
signal
string
shutil
subprocess
getpass
socket
requests
base64
ConfigParser
logging
thread
socket
hashlib
ssl
json
urllib2
datetime as dt
urllib3

```

INCLUDES
--------
```
atdsubmitter.py source file.
this README file.
```

INSTALLATION
------------
```
REST Daemon:
	- Copy the REST submission script provided to directory.
	- Give necessary execution permissions to the script
	- Make sure device has sufficient space. (primarily on partition where scripts are copied)
	- Local private environment will be created for REST daemon to store the log and configuration files.
Bro Network Sensor:
	- User should install Bro network sensor on their own as it is open source and all the documentation is available to all.
	- On configuring and running the Bro network sensor user should record the path where bro n/w sensor will extract the samples
      from configured network interface.

Follow the configuration to configure the REST daemon for sample submission to submit the samples to configured MATD (McAfee Advance Threat Defense)
for dynamic analysis, as per the configured Analyzer profile.	
```
	
COMMAND LINE ARGUMENTS
----------------------
./atdsubmitter.py ( start | stop | restart | configure | status | stats)

	start     - Start the Rest Submission daemon as per the user provided configuration.
	stop      - Stop the Rest Submission daemon 
	restart   - stop and start the Rest Submission daemon with user provided configuration.
	configure - Configure Rest Submission daemon.
	status	  - Status command will provide the status of daemon. (Running | Stopped)
	stats	  - stats command will provide the statistics of samples submission. i.e. sample submission average per hour

	
CONFIGURATION
-------------
```
./atdsubmitter.py configure :
Run in Silent mode? [y/n] : [n]					: <y/n>
Enter MATD IP                                   : x.x.x.x
Enter Username                                  : <bro user type username to login to MATD> e.g. brosensor1
Enter Analyzer Profile Id [default:' ']         : <Analyzer Profile Id> e.g. 1
Enter Absolute sample directory path            : /path/to/sample/directory/

Provide path to store files. e.g. Log files, Counter files etc.[default:<HOME>/atd-bro/] :

Do you want to delete file on submission? yes/no: no

Please provide absolute directory path to move the file's [default:<HOME>/ATDBro/samples_backup/] :

Note: Configuration is saved to file : /etc/atd-bro/atd-bro.conf

Do you want to start the REST submission? yes/no : no

Done.
```


Configuration Description:
--------------------------
```
Run in Silent mode? [y/n]: [n] 
	Default is No if nothing / n is provided.
		If NO is entered, then default Active mode will be enabled.
		Active Mode: In this mode REST daemon, will submit samples to the ATD for analysis.
	If User choose YES 
		If YES is entered Silent mode will be enabled
		Silent Mode: In this mode REST daemon, will not submit the samples to the ATD but will log all the activities 
		as Active mode. Also, maintain the statistics of average per hour sample submission.

Enter MATD IP                                   : x.x.x.x
	Enter McAfee Advance Threat Defense device IP.
	Sample submission will be done to this device.

Enter Username                                 : admin
	Using this username login will be done to the device for REST Submission.

Enter Analyzer Profile Id                      : 1
	Please do check the Analyzer Profile Id from MATD device user interface (UI) and use the same id to configure the REST Submission daemon.

Enter Absolute sample directory path            : /path/to/sample/directory/
	Enter the path of the directory where Bro network sensor will extract the samples from configured network interface.

Provide path to store files. e.g. Log files, Counter files etc.[default:<HOME DIR>/atd-bro/] :
	This is the installation path for REST daemon files like log file, counter files, samples backup etc.
	By default,
		<HOME DIR> + "/atd-bro" path will be used to store the files
	If User provides different path to store the files, then files will be created / stored at provided path.

Do you want to remove file on submission? yes/no: no
	You can choose to remove the sample / file after successful submission to MATD.
	If Yes:
		Sample will be removed i.e. Deleted.
	If No:
		Sample will be moved to the user provided directory.

	If you choose no to above yes/no question,
		you will be asked to provide the path to move the submitted files.
		
Please provide absolute directory path to move the file's [default:<HOME DIR>/ATDBro/samples_backup/] :
	If you enter without any inputs, then default path will be used to move the samples on submission.
	If you provide input i.e. Path then the samples will be moved to the specified directory on submission.

Done.
```

TROUBLESHOOTING
---------------
```
 * If failed to execute:
   - Please check if script has executable permissions provided before executing.
   
 * Failed to save the configuration
   - Please check if script has permissions to write to directory paths which are configured on configuration 
  
 * Module Error
   - Check if all the modules required by script are installed 
   - Check modules list from # RECOMMENDED MODULES # section

 * Files are not getting submitted to ATD for analysis
   - Check if ATD is UP and Running
   - Check if below configuration provided is correct
	1. IP Address
	2. Username
	3. Password
	4. Analyzer Profile
	
 * Login session creation failed
   - Check if provided password is correct
   - Check if configured user has multi login enabled in ATD UI
```

FAQ
---

	Q: Where the provided password will be saved?

	A: On start | restart user must provide the password for configured username. Password will not be saved on disk.

	Q: What is the maximum file size allowed?

	A: Maximum file size allowed is 120mb. File with size more than 120mb will be ignored.
	
	Q: What happens to the local files after submission?
	
	A: User must choose whether user wants to delete the file on submission or move the files to another directory.
	   Files will be processed as per the user instructions.
	   
	Q: What if there is no submission of files for 1-2hr? What will happen to login session?
	
	A: Session will be kept alive till user stops the daemon. 
	   And whenever the file is available for submission daemon will pick the sample and will submit to configured ATD for analysis.
	   
	Q: Is there any log rotation mechanism? 
	
	A: Yes. When log files crosses size of 100mb file will be rotated to new log file. 
		Total 10 log files will be maintained.

	Q: Are there any specific rules for sample submission from Bro to ATD?
	
	A: Yes below are the rules applied of sample submission from Bro to ATD,
	
		#### LOCAL SAMPLE HASH CHECK
		
		Atdsubmitter.py daemon maintains last unique 1000 sample hashes in memory.
		While sample submission to ATD daemon records sample hash in hash table. 
		If sample hash is already present in hash table, then sample will be skipped for submission to avoid re-submission.
		If sample hash is not present in hash table, then hash will be updated to hash table on submission. 
		            
    
		#### FILE TYPE CHECK
		
		Atdsubmitter.py daemon checks supported file type with ATD. 
		If the file type is supported by ATD then atdsubmitter daemon will submit the sample to ATD for analysis.
		If the file type is not supported by ATD then atdsubmitter daemon will not submit the sample to ATD and log the event.
		
                
		#### FILE SIZE CHECK 
		
		Before sample submission atdsubmitter daemon verify the file size allowed by ATD for supported file types.
		If sample is within the ATD file size limits for that particular file type then daemon will submit the sample to ATD for sample analysis.
		If sample is out of the file size range for that particular file type then daemon will submit the sample to ATD for sample analysis.
		
                
		#### ON SAMPLE SUBMISSION FAILURE FROM atdsubmitter TO ATD
		
		If the sample submission fails due to ATD rejection or overload  then the same sample submission will retry after 3 min of time delay to avoid failures. 
		
		
MAINTAINERS
-----------
```
Current maintainers:
	* Pravin Yarolkar (McAfee) 
	* Vishal Kumar (McAfee)
```
```
This project has been sponsored by:
	* McAfee Software India Pvt Ltd.
	  McAfee, Inc. is an American global computer security software company headquartered in Santa Clara, California.
	  It is the world's largest dedicated security technology company.
```
