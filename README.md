# Al Pastor - NIDS Dataset Creation Tool

Al Pastor is a software tool designed for generating Network Intrusion Detection System (NIDS) datasets from pcap files. The tool addresses the limitations of existing Machine Learning Intrusion Detection Systems (ML-IDS) by combining training data from public datasets with local network traffic, allowing for the detection of both known and zero-day attacks.

## Idea

In today's rapidly evolving landscape, where new threats emerge regularly, the ability to detect malicious network packets is crucial to ensuring user safety. While traditional network intrusion detection systems (NIDS) rely on packet fingerprints for detecting malicious activity, modern systems leverage machine learning techniques. However, training these machine learning models for intrusion detection requires high-quality datasets, which remain a challenge to obtain.

The objective of this thesis is to address this challenge by developing Al Pastor, a software tool that analyzes network packet data stored in pcap files and interfaces with an existing intrusion detection tool called Snort. The primary goal of Al Pastor is to generate datasets from which a neural network can be trained to effectively identify threats.

The generated datasets, like most existing systems, encompass various aspects of network traffic, including packet flow, packet header structure, and data content.
## Features

- Creation of Protocol Header Datasets: Dataset generation with protocol-specific information for different protocol stacks (e.g., ETH/IPv4/TCP, ETH/IPv4/UDP, ETH/IPv4/QUICC).
- Packet-Flow Data: Generation of Netflow-like datasets to analyze data transmission rates.
- Labeling: Assignment of labels to dataset entries based on threat detection using the Snort signature-based IDS.

## Prerequisites

Before using Al Pastor, ensure that the following dependencies are installed:

- Snort: [Installation instructions for Snort](https://snort.org)
- Argus: [Installation instructions for Argus](https://argus.info)

## Usage
```
usage: al_pastor.py [-h] -p pcap [-s snort] [--sc snort-config] [-a argus] [--ac argus-client] [--ds] [--da] [--csv] [-o O]

Process some integers.

optional arguments:
-h, --help show this help message and exit
-p pcap location of pcap file to parse
-s snort location of snort bin
--sc snort-config location of snort configuration
-a argus location of argus bin
--ac argus-client location of argus client bin
--ds do not run snort
--da do not run argus
--csv generate csv files
-o O output directory
```


For more detailed instructions and information, please refer to the [project's page](https://tsokos.dev/projects/al_pastor).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.md) file for details.
