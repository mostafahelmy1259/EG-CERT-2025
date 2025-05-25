# TimeStomp EG-CERT 2025 CTF

It was late Friday night when the notification popped up on my screen. A new CTF challenge had just dropped, and with only 109 solves so far, I knew this was my chance to climb up the leaderboard. The challenge, simply titled "TimeStamp," caught my attention immediately.

## The Challenge

The description read: "The attacker dropped malware that stomped the timestamp of malicious files according to the timestamps of the files in the same directory. Can you retrieve the logfile sequence number of the timestomped file?"

![Challenge Description](https://i.imgur.com/placeholder.jpg)

For those unfamiliar with timestomping, it's an anti-forensics technique where attackers modify file timestamps to blend in with legitimate files, making detection much harder. The challenge provided an E01 forensic image file (a common format used in digital forensics) and asked us to find the logfile sequence number of the timestomped file.

The flag format was clear: `flag{decimal_logfile_sequence_number}`. Simple enough, but the devil is always in the details.

## Setting Up My Forensic Workbench

I quickly downloaded the E01 image and set up my forensic environment. For this challenge, I needed a few essential tools:

```bash
sudo apt-get install ewf-tools sleuthkit
```

The `ewf-tools` package would help me handle the E01 image format, while `sleuthkit` would provide the necessary tools for filesystem analysis.

## Extracting the Raw Image

My first step was to extract the raw image from the E01 container. I used `ewfexport` for this:

```bash
mkdir -p ewf_mount raw_mount
ewfexport -f raw -t raw_image Timestomped.E01
```

The tool prompted me for some parameters:
- Evidence segment file size: 0 (unlimited)
- Start offset: 0
- Number of bytes to export: 1073741824 (the full image)

After a few moments of processing, I had my raw image file ready for analysis.

## Analyzing the Partition Structure

Before diving into file timestamps, I needed to understand the structure of the disk image. Using `mmls` from Sleuthkit, I examined the partition table:

```bash
mmls raw_image.raw
```

The output revealed a GPT partition table with several partitions:
```
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors
      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000000033   0000000034   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
003:  Meta      0000000002   0000000033   0000000032   Partition Table
004:  000       0000000034   0000032767   0000032734   Microsoft reserved partition
005:  001       0000032768   0002093055   0002060288   Basic data partition
006:  -------   0002093056   0002097151   0000004096   Unallocated
```

The partition of interest was clearly the "Basic data partition" starting at sector 32768.

## Listing Files and Directories

I initially tried mounting the partition, but my environment didn't support FUSE, so I had to use Sleuthkit tools directly. I used `fls` to list all files and directories:

```bash
fls -o 32768 -r raw_image.raw
```

This gave me a comprehensive listing of all files on the partition. Among the system files and directories, I noticed several document files that caught my attention:

```
r/r 39-128-1:	Case_Document_7-1.doc
r/r 43-128-1:	Case_Document_7-2.doc
r/r 45-128-1:	Case_Document_7-3.doc
r/r 46-128-1:	Case_Document_7-4.doc
r/r 47-128-1:	Case_Document_7-5.doc
r/r 48-128-1:	Case_Document_7-6.doc
r/r 49-128-1:	D44FieldAdAgree.pdf
r/r 51-128-1:	file_example_XLS_5000.xls
r/r 50-128-1:	s52-a5ugamgmt.pdf
r/r 44-128-1:	s55-K5animalServicesILA.pdf
```

These files were all in the same directory, which aligned perfectly with the challenge description about timestomping files to match others in the same directory.

## Extracting File Timestamps

To identify the timestomped file, I needed to examine the timestamps of all these files. In NTFS (which this partition was using), file timestamps are stored in the Master File Table (MFT). I used `istat` to extract detailed information about each file:

```bash
mkdir -p timestamps
for file in $(fls -o 32768 -p raw_image.raw | grep -v '\$' | grep -v 'System Volume Information' | grep -v 'RECYCLE.BIN' | awk '{print $2}' | cut -d ':' -f1); do 
    istat -o 32768 raw_image.raw $file >> timestamps/all_timestamps.txt
done
```

This command extracted the metadata for all non-system files and saved it to a text file for analysis.

## The Hunt for the Timestomped File

Now came the detective work. I needed to look for anomalies in the timestamps. In NTFS, each file has multiple timestamps:

1. Creation time
2. Modification time
3. MFT modification time
4. Access time

Additionally, NTFS maintains these timestamps in two attributes:
- $STANDARD_INFORMATION (SI)
- $FILE_NAME (FN)

When files are legitimately created and modified, both sets of timestamps are updated. However, most timestomping tools only modify the SI attributes, leaving the FN attributes untouched. This discrepancy is a telltale sign of timestomping.

Another critical piece of information in NTFS is the $LogFile Sequence Number (LSN), which is incremented with each filesystem transaction. A file with a significantly higher LSN than its neighbors, but with timestamps that match those neighbors, is highly suspicious.

I sorted the files by their LSNs:

```bash
grep -A 5 "LogFile Sequence Number:" timestamps/all_timestamps.txt | sort
```

The output revealed something very interesting:

```
$LogFile Sequence Number: 2131072
$LogFile Sequence Number: 2131100
$LogFile Sequence Number: 2131128
$LogFile Sequence Number: 2131156
$LogFile Sequence Number: 2131184
$LogFile Sequence Number: 2131212
$LogFile Sequence Number: 2131608
$LogFile Sequence Number: 2131636
$LogFile Sequence Number: 2131664
$LogFile Sequence Number: 14699247
```

One file stood out dramatically: the one with LSN 14699247, which was orders of magnitude higher than all the others (which were around 2131xxx).

## Identifying the Culprit

To confirm which file had this anomalous LSN, I extracted its details:

```bash
grep -A 30 "Entry:" timestamps/all_timestamps.txt | grep -B 5 -A 30 "LogFile Sequence Number:" | grep -A 30 "Name:" | grep -B 30 "file_example_XLS_5000.xls" > timestamps/xls_file_details.txt
```

The output confirmed my suspicion:

```
Entry: 51        Sequence: 2
$LogFile Sequence Number: 14699247
Allocated File
Links: 1
$STANDARD_INFORMATION Attribute Values:
Flags: Read Only, Archive
Owner ID: 0
Security ID: 264  (S-1-5-21-321011808-3761883066-353627080-1000)
Created:	2022-10-04 18:03:33.000000000 (EDT)
File Modified:	2022-10-04 17:52:23.000000000 (EDT)
MFT Modified:	2022-10-04 17:52:23.000000000 (EDT)
Accessed:	2022-10-04 18:03:59.000000000 (EDT)
$FILE_NAME Attribute Values:
Flags: Read Only, Archive
Name: file_example_XLS_5000.xls
```

The file `file_example_XLS_5000.xls` had an LSN of 14699247, much higher than any other file. Additionally, I noticed something else suspicious: the timestamps in the SI attribute had been truncated to remove microseconds (they all ended with .000000000), while legitimate files had microsecond precision.

Looking at the timestamps more closely, I could see they matched those of Case_Document_7-1.doc:

```
Created:	2022-10-04 18:03:33.639233400 (EDT)  // Original file
Created:	2022-10-04 18:03:33.000000000 (EDT)  // Timestomped file

File Modified:	2022-10-04 17:52:23.959087800 (EDT)  // Original file
File Modified:	2022-10-04 17:52:23.000000000 (EDT)  // Timestomped file
```

This was clear evidence of timestomping! The attacker had modified the XLS file's timestamps to match those of the DOC file, but they couldn't change the LSN, which revealed the deception.

## The Flag

With the timestomped file identified and its logfile sequence number retrieved, I had my answer:

```
flag{14699247}
```

I submitted the flag and watched as my position on the leaderboard climbed. Another challenge conquered!

## Lessons Learned

This challenge highlighted several important aspects of digital forensics:

1. **Timestomping is detectable**: While attackers can modify file timestamps, they often leave other forensic artifacts untouched.

2. **NTFS maintains multiple timestamp records**: The dual timestamp attributes (SI and FN) provide a way to detect tampering.

3. **Logfile Sequence Numbers are valuable**: LSNs provide a chronological record of filesystem changes that attackers typically can't manipulate.

4. **Forensic tools matter**: Having the right tools (like Sleuthkit) makes all the difference in digital investigations.

For aspiring digital forensics practitioners, this challenge demonstrates the importance of looking beyond the obvious. Timestamps can lie, but the filesystem usually keeps other records that tell the truth.

## Conclusion

Digital forensics is often like solving a puzzle where some pieces have been deliberately altered. The key is knowing where to look for the pieces that can't be changed. In this case, the $LogFile Sequence Number was the smoking gun that revealed the timestomped file.

The next time you're investigating a potential compromise, remember to look beyond the timestamps. The truth is often hidden in the metadata that attackers forget to modify or can't access.

Happy hunting!

---

*Note: This write-up is based on a CTF challenge. The techniques described are used by real digital forensics investigators to detect anti-forensics measures like timestomping.*
