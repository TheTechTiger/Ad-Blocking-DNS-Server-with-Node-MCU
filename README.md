---

# Ad-Blocking DNS Server with Node MCU

This project implements an ad-blocking DNS server using Node MCU (ESP8266) microcontroller, capable of resolving domain names, performing reverse DNS lookups, and blocking unwanted advertisements. It provides a customizable DNS resolution service, offering flexibility and control over DNS responses while helping to improve browsing experience by blocking ads.

## Features

- **Custom DNS Resolution:** Resolve domain names according to predefined mappings.
- **Reverse DNS Lookup:** Provide reverse DNS lookup functionality for IP addresses.
- **Ad-Blocking:** Block unwanted advertisements by filtering DNS requests.
- **Cache Management:** Maintain a cache of recent DNS transactions to improve response times and reduce network traffic.
- **Flexible Configuration:** Easily configure WiFi settings and DNS mappings to adapt to different network environments.
- **LED Indicator:** Visual indication of the device's status using a built-in LED.

## Getting Started

### Hardware Requirements

- Node MCU (ESP8266) microcontroller board
- USB cable for programming and power supply
- LED (optional) for visual indication

### Software Requirements

- Arduino IDE or PlatformIO for programming the Node MCU
- Required Libraries:
  - ESP8266WiFiMulti
  - WiFiUdp
  - ArduinoJson

### Installation

1. Clone or download the project repository.
2. Open the project in Arduino IDE or PlatformIO.
3. Install the ArduinoJSON library if not already installed.
4. Connect the Node MCU board to your computer via USB.
5. Select the appropriate board and port in the Arduino IDE.
6. Upload the sketch to the Node MCU board.

### Usage

1. Power on the Node MCU board.
2. Monitor the serial output for debugging information (`74880` baud rate).
3. The built-in LED indicates the device's status:
    ON --> connected and DNS Server running
    Blinking --> Connection to host AP failed
4. Configure the network settings using the serial monitor(send 'help' command for detailed information)

## Troubleshooting

- If encountering connection issues, ensure correct WiFi credentials are provided.
- Check serial output for debugging information and error messages.
- Verify hardware connections and ensure the Node MCU board is properly powered.
- If the value provided is shown invalid, Use proper Value Identifiers(/x: and :x\)
