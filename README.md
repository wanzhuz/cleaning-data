# Data Cleaning and Analyzing
<strong>Overview: </strong>Clean and organize data to identify and understand trends.</li>
As computers/operating systems run, different events that occur are logged and recorded in various “log” files. These include events such as
<ul>
  <li>attempted logins to the machine from others</li>
  <li>logins from the same machine</li>
  <li>running commands as another user via sudo</li>
  <li>adding users</li>
</ul>

We want to monitor all login attempts to help identify and prevent potential attacks on the machine. The data we will be working with is a merged log file consisting of 5 different log files from different machines (10.9 MB).
The structure of the log file message is usually METADATA followed by the message from the machine.

### Task
We create a data-frame with a row for each log message line. The data-frame consists of the following columns:
<ul>
  <li>date-time</li>
  <li>name of host</li>
  <li>application (app)</li>
  <li>process ID (PID)</li>
  <li>message</li>
  <li>name of the log file</li>
</ul>

We check and analyze our data by:
<ul>
  <li>check that PIDs are all numbers</li>
  <li>verify the number of lines in each log file</li>
  <li>check the range of date-times for each message vs. the range of date-times for each of the different log files</li>
  <li>find how many days each log file spans</li>
  <li>is there a pattern in the application names?</li>
  <li>is the host value constant for all records in each log file?</li>
  <li>identify the most common daemons/programs that are logging information on each of the different hosts </li>
</ul>

Now, we check for valid and invalid logins. This will help us identify which IP addresses and users to look out for.
<ul>
  <li>collect the usernames and IP addresses of the valid logins</li>
  <li>collect the usernames and IP addresses of the invalid logins</li>
</ul>

Finally, we check what the executables/programs run via sudo are. Identify their user and machine.

