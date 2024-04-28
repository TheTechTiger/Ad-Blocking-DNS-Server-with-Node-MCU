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
3. Install the required libraries if not already installed.
4. Specify in the WiFi network to be connected to in the code(Replace `SSID` and `PASS` with your credentials)
5. Connect the Node MCU board to your computer via USB.
6. Select the appropriate board and port in the Arduino IDE.
7. Upload the sketch to the Node MCU board.

### Usage

1. Power on the Node MCU board.
2. Monitor the serial output for debugging information (`74880` baud rate).
3. The built-in LED indicates the device's status: ON when connected, OFF when disconnected.
4. Send DNS queries to the IP address of the Node MCU board.
5. Monitor the serial output for DNS query processing details.

## Customization

- Modify WiFi network settings (`addAP` function) to match your network credentials.
- Adjust DNS mappings (`Maps` object) to resolve custom domain names.
- Customize cache size and expiration time to suit your requirements (`cacheList` class).
- Add additional DNS rules for ad-blocking by updating the DNS resolution logic in the `loop` function.
- To use this as an ad-blocker, Map all ad-providing domains to 0.0.0.0 in the JSONDocument Maps

## Troubleshooting

- If encountering connection issues, ensure correct WiFi credentials are provided.
- Check serial output for debugging information and error messages.
- Verify hardware connections and ensure the Node MCU board is properly powered.
