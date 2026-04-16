## Tools List

- **stalker:** designed to help the investigator find all the files related to a person in a device.
- **dirwatcher:** keep track of any change in the selected folders every X seconds.
- **wpIOChecker:** scan through a WordPress installation folder for changes. It compares a previous WP status report with a more recent one, so it can help find hidden web shell. Obviously the changes to the pages are not detected since it doesn't have access to DB.
- **pshunter:** helps during analysis or in case of compromise to capture new or specific processes and make chosen actions. *ATM please note that in Windows the use of '-f' option with an update time less than 1sec could give problems in stopping the program with CTRL+C since "interrupt" is not correctly captured due to the too fast refresher frequency compared to the speed of access to files*.
- **ipinfo:** automates the information collection process of malicious IPs for the reports drafting.
- **CatchWatch:** intercept and save volatile files or files that are deleted immediately after they are created and used, during malware execution.
- **pattern_extractor_b64:** generate blob-aligned chunks for target strings to create YARA rules.
