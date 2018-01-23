# LHFScan (Lowest Hanging Fruit Scan)

A lowest hanging fruit scan using python and nmap libraries
A script to identify the lowest hanging fruit on a network without having to sift through NMAP outputs.
This script collates all known
      + web services,
      + SMB shares, 
      + FTP,
      + SSH,
      + Telnet,
      + SMTP 
      + and dangerous hosts including XP and 2003
      
Includes rudimentary fixing of TCPwrapper issues.

Future versions to include scans for various known issues such as GPO passwords and PII on shared areas.

Want to contribute? Feel free to add signatures to detect services of interest.
