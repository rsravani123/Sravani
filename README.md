# VRV Assignment

## VRV Security’s Python Intern Assignment  
**Assignment: Log Analysis Script**

---

## Objective  
The goal of this assignment is to assess your ability to write a Python script that processes log files to extract and analyze key information. This assignment evaluates your proficiency in file handling, string manipulation, and data analysis—essential skills for cybersecurity-related programming tasks.

---

## Core Requirements  

### 1. **Count Requests per IP Address**  
- Parse the provided log file to extract all IP addresses.  
- Calculate the number of requests made by each IP address.  
- Sort and display the results in descending order of request counts.  

#### Example Output:
```
IP Address    Request Count
192.168.1.1   234
203.0.113.5   187
10.0.0.2      92
```

---

### 2. **Identify the Most Frequently Accessed Endpoint**  
- Extract the endpoints (e.g., URLs or resource paths) from the log file.  
- Identify the endpoint accessed the highest number of times.  
- Provide the endpoint name and its access count.  

#### Example Output:
```
Most Frequently Accessed Endpoint:
/home (Accessed 403 times)
```


---

### 3. **Detect Suspicious Activity**  
- Identify potential brute force login attempts by:  
  - Searching for log entries with failed login attempts (e.g., HTTP status code `401` or a specific failure message like "Invalid credentials").  
  - Flagging IP addresses with failed login attempts exceeding a configurable threshold (default: 10 attempts).  

#### Example Output:
Suspicious Activity Detected:
```
IP Address       Failed Login Attempts
192.168.1.100    56
203.0.113.34     12
```

---

### 4. **Output Results**  
- **Display the results** in a clear, organized format in the terminal.  
- **Save the results** to a CSV file named `log_analysis_results.csv` with the following structure:  

#### CSV Structure:  
- **Requests per IP**:  
  - Columns: `IP Address`, `Request Count`  

- **Most Accessed Endpoint**:  
  - Columns: `Endpoint`, `Access Count`  

- **Suspicious Activity**:  
  - Columns: `IP Address`, `Failed Login Count`  

---

### Deliverables:  
- Python script implementing the above functionalities.  
- Example log file (if applicable).  
- Generated CSV file (`log_analysis_results.csv`).  
