## Purpose
ChainRecon is a system designed to help analyze IoT devices for security research. Instead of running a bunch of different commands manually every time to test a device, this script automates the whole process - from network setup to traffic capture to SSL analysis.

The main goal is to figure out what an IoT device is doing on the network: what servers it talks to, what protocols it uses, and whether it has any obvious security issues.

## Requirements
- has a CLI parser that validates input for interface, router, and target ip values
- provides a menu with 4 modes: network setup, device scanning, traffic capture & analysis, and SSL/TLS analysis
- provides a preset value for possible variables if not specified by the user
- establish a man-in-the-middle position, with the ability to log network traffic through external tools after the tool has been used to set up the network
- be able to capture network traffic and save it to a file for later analysis
- analyze network traffic, extracting information such as DNS queries, HTTP requests, TLS/HTTPS destinations, and protocol usage statistics
- be able to perform SSL/TLS analysis and perform a vulnerability check on the device's SSL implementation, including checking for weak ciphers and outdated TLS versions
- be able to generate a comprehensive report based on the captured traffic and analysis results
- give logs to help track steps taken during each process
- prompt the user and exit gracefully when an error occurs, providing helpful error messages to guide the user in resolving the issue
- designed to be modular and extensible, allowing for easy addition of new features and analysis techniques in the future

## Future Features
- allows for plug-ins to translate data into user-customizable reports (using a provided base class)
- ability to resume interrupted sessions or re-run specific steps without starting over


