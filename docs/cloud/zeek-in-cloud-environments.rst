Zeek in Cloud Environments (AWS, Azure, GCP)
===========================================

Introduction
------------

Deploying Zeek in cloud environments requires a different approach compared to
traditional on‑premises networks. Cloud platforms do not expose raw packets
directly, and traffic visibility depends on provider‑specific mirroring
features. This document describes how to deploy Zeek using native traffic
mirroring mechanisms in Amazon Web Services (AWS), Microsoft Azure, and Google
Cloud Platform (GCP), and outlines the limitations and considerations for each
environment.

Cloud Traffic Visibility Overview
---------------------------------

Cloud networks are fully virtualized, and packet access is restricted by
design. Traditional SPAN or TAP methods are not available. Instead, each cloud
provider offers a traffic mirroring feature that allows selected network
traffic to be copied to a monitoring instance. Zeek can process this mirrored
traffic in real time, provided that the deployment is sized appropriately and
placed close to the mirrored source.

AWS Deployment Using VPC Traffic Mirroring
------------------------------------------

Overview
~~~~~~~~

AWS provides VPC Traffic Mirroring, which allows copying traffic from Elastic
Network Interfaces (ENIs) to a monitoring instance. This is the primary method
for obtaining packet‑level visibility in AWS.

Supported Sources
~~~~~~~~~~~~~~~~~

- EC2 instances (Nitro‑based)
- ENIs attached to EC2 or load balancers
- Container workloads using ENI‑based networking

Architecture
~~~~~~~~~~~~

A typical deployment includes:

- A Traffic Mirror Source (ENI)
- A Traffic Mirror Filter (protocol and port selection)
- A Traffic Mirror Target (Zeek instance)

Zeek runs on an EC2 instance or container and processes mirrored packets using
AF_PACKET or DPDK.

Deployment Steps
~~~~~~~~~~~~~~~~

1. Create a Traffic Mirror Target.
2. Create a Traffic Mirror Filter to limit mirrored traffic.
3. Create a Traffic Mirror Session linking the ENI to the target.
4. Deploy Zeek on an EC2 instance with sufficient CPU and network bandwidth.
5. Configure Zeek to process traffic from the mirrored interface.

Considerations
~~~~~~~~~~~~~~

- Traffic mirroring incurs per‑GB charges.
- Filtering is recommended to reduce cost.
- c6i, m6i, or similar instance types provide stable performance.
- Mirrored traffic is unidirectional; Zeek reconstructs flows from mirrored packets.

Azure Deployment Using vTAP and Packet Capture
----------------------------------------------

Overview
~~~~~~~~

Azure provides multiple visibility mechanisms, but only Virtual Network TAP
(vTAP) offers continuous packet mirroring suitable for Zeek. Availability
varies by region.

Traffic Visibility Options
~~~~~~~~~~~~~~~~~~~~~~~~~~

- vTAP: Continuous packet mirroring to a collector VM.
- Packet Capture: On‑demand capture for troubleshooting.
- NSG Flow Logs: Metadata only; not usable by Zeek.

Architecture
~~~~~~~~~~~~

When vTAP is available:

- vTAP mirrors traffic from selected NICs to a Zeek VM.
- Zeek processes packets using AF_PACKET.

Where vTAP is not available:

- Only offline analysis using Packet Capture is possible.

Considerations
~~~~~~~~~~~~~~

- vTAP availability is region‑dependent.
- NSG Flow Logs cannot be parsed by Zeek.
- Throughput depends on VM size and storage performance.

GCP Deployment Using Packet Mirroring
-------------------------------------

Overview
~~~~~~~~

GCP provides Packet Mirroring, which mirrors traffic from VM instances, load
balancers, or GKE nodes to a collector instance.

Architecture
~~~~~~~~~~~~

A typical deployment includes:

- A Packet Mirroring Policy
- Source VMs or subnets
- A Zeek VM as the collector

Zeek processes mirrored packets using AF_PACKET or DPDK.

Deployment Steps
~~~~~~~~~~~~~~~~

1. Create a Packet Mirroring Policy.
2. Select source instances or subnets.
3. Select the Zeek VM as the collector.
4. Configure Zeek to process mirrored traffic.

Considerations
~~~~~~~~~~~~~~

- Packet mirroring incurs per‑GB charges.
- Filtering reduces cost and improves performance.
- n2‑standard or c2‑standard instances provide stable throughput.

Zeek in Containerized Environments (EKS, Azure Kubernetes Service, GKE)
--------------------------------------------------

Overview
~~~~~~~~

Running Zeek inside Kubernetes requires node‑level visibility. Cloud CNI
plugins often hide pod‑to‑pod traffic, so mirroring must occur at the node
interface.

Deployment Models
~~~~~~~~~~~~~~~~~

- DaemonSet (one Zeek instance per node)
- Dedicated Zeek node pool
- Sidecar deployments (limited visibility)

Considerations
~~~~~~~~~~~~~~

- Host networking is recommended.
- AF_PACKET provides stable performance.
- Mirroring must target node NICs, not pod interfaces.

Logging and Integration
-----------------------

Zeek logs can be exported to:

- Amazon S3
- Azure Blob Storage
- Google Cloud Storage
- Kafka clusters
- SIEM platforms such as Splunk, Elastic, Microsoft Sentinel, and Google Chronicle

Cloud‑Relevant Detection Use Cases
----------------------------------

AWS
~~~

- Metadata service probing (IMDSv1/v2)
- Lateral movement between EC2 instances
- DNS tunneling

Azure
~~~~~

- SMB and LDAP traffic inside VNets
- TLS anomalies
- VM‑to‑VM scanning

GCP
~~~

- Metadata server access attempts
- Internal scanning
- Suspicious service‑to‑service traffic

References
----------

- AWS VPC Traffic Mirroring:
  https://docs.aws.amazon.com/vpc/latest/mirroring/what-is-traffic-mirroring.html
- Azure Virtual Network TAP:
  https://learn.microsoft.com/azure/virtual-network/virtual-network-tap-overview
- GCP Packet Mirroring:
  https://cloud.google.com/vpc/docs/packet-mirroring
- Zeek Documentation:
  https://docs.zeek.org
- MITRE ATT&CK Cloud Matrix:
  https://attack.mitre.org/matrices/enterprise/cloud/
