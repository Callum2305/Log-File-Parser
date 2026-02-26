'''
Assignment:     1
Student:     Daniel V
Student:     Callum Matthews
Class:          2nd year Scripting for Cybersecurity

Note (February 2026):   This project was completed in 2025, by myself and another Student. I am uploading a copy of it here to my personal account, without their second name or ID number.
                        There were no other changes made apart from removing his second name and ID. I also have been given full permission to upload this here by Daniel, as do I give him
                        permission to upload it to his own account if he pleases.


'''
from datetime import timedelta                                          #Imports timedelta as a data type, and datetime to represent time durations
import matplotlib.pyplot as plt                                         #Imports library to visualise data with graphs
#if code dosen't work do "pip install matplotlib" in the terminal

import json
from collections import defaultdict
from datetime import datetime

LOGFILE = "CA1_project.log"                                             #Variable name to declare the name of the logifle

def parse_auth_line(line):  
    parts = line.split()                                                #split line into different parts
    ts_str = " ".join(parts[0:3])                                       #joins first three parts together to make a timestamp
    try:
        ts = datetime.strptime(f"2025 {ts_str}", "%Y %b %d %H:%M:%S")   #assumeing year is 2025, make timestamp using ts extraced from line
    except Exception:                                                   #Exept, means that nothing will happen if there is nothing found
        ts = None


    ip = None
    event_type = "other"
    if "Failed password" in line:
        event_type = "failed"
    elif "Accepted password" in line or "Accepted publickey" in line:
        event_type = "accepted"
    if " from " in line:                                                # if from in line, we know there will be an ip address, from an ssh login
        try:                                                            #if from exists, get line immediatly after 'from'
            idx = parts.index("from")
            ip = parts[idx+1]
        except (ValueError, IndexError):                                #if there is no from, just return nothing to prevent program breaking
            ip = None
    return ts, ip, event_type                                           #return three extracted parts, or a truple if you want to be pedantic

#Important part, taken from Mark: Main function
if __name__ == "__main__":
    per_ip_timestamps = defaultdict(list)
    with open(LOGFILE) as f:
        for line in f:
            ts, ip, event = parse_auth_line(line)                       #calls parse function to extract ts ip and event_type
            if ts and ip and event == "failed":                         #checks that ts and ip are not null, and that event=="failed", so avoid non failed
                per_ip_timestamps[ip].append(ts)                        #add time stamp to lsit of timestamps for specific ip address

#Brute force detection:
incidents = []                                                          #currently empty list, will store attack information here
window = timedelta(minutes=10)                                          #setting a timeframe, 10 minutes

for ip, times in per_ip_timestamps.items():                             #loop through each ip and its timestamps
    times.sort()                                                        #sort timestamps in chronological order
    n = len(times)                                                      #variable to hold num of failed timestamps for current IP
    i = 0                                                               #loop counter, marks start point as index 0
    while i < n:                                                        #loop through each timestamp index, basically whatever number i is currently
        j = i                                                           #new variable with a terrible name cause ive no imagineation, this is what counts failed attemps, i is index, this is fails
        while j + 1 < n and (times[j+1] - times[i]) <= window:          #expand time frame or window from index postion i outwards, move j forward as long as i have another timestamp within range of 10mins
            j += 1                                                      #j ends with last timestamp within same time window starting at index point i
        count = j - i + 1                                               #how many failed logins in that window
        if count >= 5:                                                  #take data and put in list 
            incidents.append({
                "ip": ip,
                "count": count,
                "first": times[i].isoformat(),                          #i is index of first time, iso format makes timestamp readable
                "last": times[j].isoformat()                            #j is now last time
            })
# advance i past this cluster to avoid duplicate overlapping reports:
            i = j + 1                                                   #stops us from having segregated counts of the same ip
        else:
            i += 1                                                      #if fewer than 5 failed attempts move on

# combine counts by IP
summary = []                                                            #prevents repeats of same ip, currently empty list, will hold one summary entery from final output per IP
for ip, times in per_ip_timestamps.items():                             #loop through ip dict, take ip and which time it failed
    times.sort()                                                        #sort to chronological order
    total_count = len(times)                                            #how many times that ip failed overall
    summary.append({                                                    #appened summary with details to then go and export to our file
        "ip": ip,
        "total_count": total_count,
        
    })

#From here we start migrating our data to the report. First print a header:
with open ('brute_force_attempts.txt', 'w') as f:
    f.write("BRUTE FORCE ATTEMPTS REPORT:\n")
    f.write("PURPOSE: Extracts failed logins and prints out the ip addresses and prints number of attempts within a ten minute window\n")
    f.write("Print each IP, and how many times it appears as a failed login within a 10 minute window, as there are multiple 10 minute windows, there are multiple instances of same IP:\n\n")
for event in incidents:                                                 # loop through the incidents dict reading each line as a variable I called event, and extra the values from the dictionary
    ip = event["ip"]    
    count = event["count"]
    first = event["first"]
    last = event["last"]
    
    output = (f"IP: {ip}, Failed Attempts: {count}, First Attempt: {first}, Last Attempt: {last}") #f makes it a formatted string

    print(output)                                                       #print to terminal to check its working
    with open('brute_force_attempts.txt', 'a') as f:
        f.write(output + "\n")                                          #now printing to file, new line each time
with open('brute_force_attempts.txt', 'a') as f:
    f.write("\nTotal count of failed attemps per login: \n\n")

# print and write results of total count for each individual failed IP address
for event in summary:
#f makes it a formatted string
    output = (f"IP: {event['ip']}, Failed Attempts: {event['total_count']}")
    
    print(output)                                                       #output to terminal for debugging
    with open('brute_force_attempts.txt', 'a') as f:
        f.write(output + "\n")  #new line to make it look better



summary.sort(key=lambda x: x['total_count'], reverse=True)              #summary is a list of dictionaries, key=lambda x: tells python to sort based on total_count value

top_5 = summary[:5]                                                     #sorts the list and only keeps the first 5 entries(top 5 attackers)

ips = [item['ip'] for item in top_5]                                    #list of ip's
counts = [item['total_count'] for item in top_5]                        #list of their corresponding total failed attempts

plt.figure(figsize=(10, 6))                                             #width=10, height=6
plt.bar(ips, counts, color='black')                                     #color of the bars in the graph
plt.xlabel('IP Address')                                                #name of x-axis
plt.ylabel('Total Failed Attempts')                                     #name of y-axis
plt.title('Top 5 IP Addresses of the attackers')
plt.xticks(rotation=45, ha='right')                                     #rotates the x-axis lable to make it readable, ha=right horizontaly aligns the lables to the right side
plt.tight_layout()                                                      #prevents overlap

max_count = max(counts)                                                 #finds the highest number of the attempts 
plt.ylim(0, max_count + max_count * 0.1) 

plt.savefig('Top_5_Attackrs.png')                                       #Saves the file under specified name
plt.close()                                                             #closes 

with open('brute_force_attempts.txt', 'a') as f:
    f.write(f"\nGraph of top 5 attackers saved as: Top_5_Attackers.png\n")

