Calimero-core [![CI with Gradle](https://github.com/calimero-project/calimero-core/actions/workflows/gradle.yml/badge.svg)](https://github.com/calimero-project/calimero-core/actions/workflows/gradle.yml)
=============
~~~ sh
git clone https://github.com/calimero-project/calimero-core.git
~~~

Calimero-core provides (secure) KNX communication protocols, KNX datapoint & property access, and management functionality. [Java SE 11](https://jdk.java.net/archive/) (_java.base_) is the minimum required runtime environment.
Calimero was developed with a focus on applications that run on embedded devices and require a small footprint.

Code examples for using this library are shown in the [introduction](https://github.com/calimero-project/introduction).


Supported Features
--------

### Access Protocols
* KNX IP Secure
    * Discovery and Self-description
    * Tunneling
    * Multicast ([example](https://github.com/calimero-project/introduction/blob/master/src/main/java/KnxipSecure.java) of creating a secure network link)
    * Busmonitor
    * Device Management
* KNXnet/IP
    * Discovery and Self-description
    * Tunneling
    * Routing
    * Busmonitor
    * Device Management
* KNX IP
* KNX RF USB
* KNX USB
* KNX FT1.2 protocol (serial connections using EMI2 or cEMI)
* TP-UART (access TP1 networks over serial connections)
* BAOS (Bus Access und Object Server)

### Process Communication
* DPT encoding/decoding of Java/KNX data types
* Process Communicator client
* Group Monitor
* KNX Data Secure

#### Supported Datapoint Types (DPTs)
* 1.x - Boolean, e.g., Switch, Alarm
* 2.x - Boolean controlled, e.g., Switch Controlled, Enable Controlled
* 3.x - 3 Bit controlled, e.g., Dimming, Blinds
* 5.x - 8 Bit unsigned value, e.g., Scaling, Tariff information
* 6.x - 8 Bit signed value, e.g., Percent (8 Bit), Status with mode
* 7.x - 2 octet unsigned value, e.g., Unsigned count, Time period
* 8.x - 2 octet signed value, e.g., Percent, Delta time seconds
* 9.x - 2 octet float value, e.g., Temperature, Humidity
* 10.x - Time
* 11.x - Date
* 12.x - 4 octet unsigned value
* 13.x - 4 octet signed value, e.g., Counter pulses, Active Energy
* 14.x - 4 octet float value, e.g., Acceleration, Electric charge
* 16.x - String, e.g., ASCII string, ISO-8859-1 string (Latin 1)
* 17.x - Scene number
* 18.x - Scene control
* 19.x - Date with time
* 20.x - 8 Bit enumeration, e.g., Occupancy Mode, Blinds Control Mode
* 21.x - Bit array of length 8, e.g., General Status, Room Heating Controller Status
* 22.x - Bit array of length 16, implemented are DPT 22.101 and DPT 22.1000
* 28.x - UTF-8 string
* 29.x - 64 Bit signed value, e.g., Active Energy, Apparent energy
* 229.001 - M-Bus metering value, with the various M-Bus VIF/VIFE codings
* 232.x - RGB color value
* 242.600 - xyY color
* 243.600 - color transition xyY
* 249.600 - brightness & color temperature transition
* 250.600 - brightness & color temperature control
* 251.600 - RGBW color 
* 252.600 - relative control RGBW
* 253.600 - relative control xyY
* 254.600 - relative control RGB

### Network Monitor / Busmonitor
Access via KNXnet/IP, KNX USB, KNX RF USB, TP-UART, and FT1.2

#### Raw Frame Decoding
* TP1
* KNX IP
* PL110
* RF

### Management
* KNX Management Layer
* KNX Management Procedures
* cEMI Local Device Management
* KNX Data Secure

### EMI Support
* cEMI standard and extend L-Data
* cEMI Busmonitor 
* cEMI Device Management
* EMI1/2 standard L-Data 
* EMI1/2 Busmonitor

### Network Buffer
* State/command-based datapoint buffer to answer .reqs, buffer incoming .ind updates


Logging
-------

Calimero uses the [System.Logger](https://docs.oracle.com/en/java/javase/19/docs/api/java.base/java/lang/System.Logger.html). Bind any desired logging frameworks of your choice.


Testing
-------

For unit tests, Calimero provides a [test network](https://github.com/calimero-project/calimero-testnetwork) consisting of a [KNXnet/IP server](https://github.com/calimero-project/calimero-server) and a virtual KNX network with two [KNX devices](https://github.com/calimero-project/calimero-device). The complete test network is implemented in software, and can be executed in any J2SE runtime environment. The network provides the remote KNXnet/IP endpoint for executing unit tests for KNXnet/IP tunneling, busmonitoring, routing, device management, and KNX IP protocols. The same network setup is used for Calimero Travis CI.

Start the test network (`gradle run`) in the directory "_calimero-core/test/testnetwork-launcher_" before running any KNXnet/IP or KNX IP tests. When using Gradle, KNXnet/IP tests can be excluded via `useJUnitPlatform() { excludeTags 'knxnetip' }`.

Currently, the TP-UART and FT1.2 protocols can only be tested if the corresponding hardware is available. 


More Features, Tools, Examples
------------------------------

* [introduction](https://github.com/calimero-project/introduction) provides code examples in Java and Kotlin for programming with Calimero.
* [calimero-tools](https://github.com/calimero-project/calimero-tools) offers command-line tools for (secure) KNX process communication, monitoring, and management, BAOS communication, and ETS 5 datapoint import.
* [calimero-gui](https://github.com/calimero-project/calimero-gui) provides a graphical user interface (based on SWT) for (secure) process communication, monitoring, and management.
* [calimero-server](https://github.com/calimero-project/calimero-server) is the Calimero KNXnet/IP Server and provides KNXnet/IP (Secure) access to KNX networks.
* [calimero-device](https://github.com/calimero-project/calimero-device) is the communication stack to implement a KNX device.
* [serial-native](https://github.com/calimero-project/serial-native) provides native libraries for serial port access (using JNI) on Windows, Linux, and MacOS.
* [import-ets-xml](https://github.com/calimero-project/import-ets-xml) imports ETS XML KNX datapoints for use with Calimero (ETS 5.7 and later is not supported, use [calimero-tools](https://github.com/calimero-project/calimero-tools)).
