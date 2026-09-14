import sys
import os

# Force Python to use the app folder from this project
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.insert(0, PROJECT_ROOT)

from app.security_engine import SecurityAssessmentEngine

import argparse
import json
import subprocess
import tempfile
import pandas as pd

from app.security_engine import SecurityAssessmentEngine

import argparse
import json
import os
import subprocess
import tempfile
import pandas as pd


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# ---------------------------------------------------------
# Parse command-line argument
# ---------------------------------------------------------

parser = argparse.ArgumentParser(
    description="Extract features from an IPsec PCAP and run the Security Assessment Engine."
)

parser.add_argument(
    "pcap_file",
    help="Path to the PCAP or PCAPNG file"
)

args = parser.parse_args()

INPUT_PCAP = os.path.abspath(args.pcap_file)

# ---------------------------------------------------------
# Validate input
# ---------------------------------------------------------

if not os.path.isfile(INPUT_PCAP):
    raise FileNotFoundError(
        f"PCAP file not found: {INPUT_PCAP}"
    )

if not os.path.isfile(TSHARK_PATH):
    raise FileNotFoundError(
        f"TShark not found at: {TSHARK_PATH}"
    )


# ---------------------------------------------------------
# Extract fields using TShark
# ---------------------------------------------------------

print("===== PCAP =====")
print(f"Input: {INPUT_PCAP}")

with tempfile.NamedTemporaryFile(
    suffix=".tsv",
    delete=False
) as temp_file:

    TEMP_TSV = temp_file.name


tshark_command = [
    TSHARK_PATH,
    "-r",
    INPUT_PCAP,
    "-T",
    "fields",
    "-E", "header=y",
    "-E", "separator=\t",
    "-E", "quote=d",
    "-e", "frame.number",
    "-e", "frame.time_epoch",
    "-e", "frame.len",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "ip.proto",
]


try:

    with open(
        TEMP_TSV,
        "w",
        encoding="utf-8",
        newline=""
    ) as output_file:

        subprocess.run(
            tshark_command,
            stdout=output_file,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )


    # -----------------------------------------------------
    # Load TShark output
    # -----------------------------------------------------

    df = pd.read_csv(
        TEMP_TSV,
        sep="\t",
        encoding="utf-8"
    )


    # -----------------------------------------------------
    # Clean numeric fields
    # -----------------------------------------------------

    for column in [
        "frame.number",
        "frame.time_epoch",
        "frame.len"
    ]:

        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )


    df = df.dropna(
        subset=[
            "frame.time_epoch",
            "frame.len"
        ]
    )


    # -----------------------------------------------------
    # Basic flow statistics
    # -----------------------------------------------------

    packet_count = len(df)

    total_bytes = df["frame.len"].sum()

    start_time = df["frame.time_epoch"].min()
    end_time = df["frame.time_epoch"].max()

    flow_duration = end_time - start_time


    if flow_duration > 0:

        packets_per_second = (
            packet_count / flow_duration
        )

        bytes_per_second = (
            total_bytes / flow_duration
        )

    else:

        packets_per_second = 0
        bytes_per_second = 0


    # -----------------------------------------------------
    # Determine endpoints
    # -----------------------------------------------------

    src_ips = (
        df["ip.src"]
        .dropna()
        .astype(str)
    )

    dst_ips = (
        df["ip.dst"]
        .dropna()
        .astype(str)
    )

    all_ips = pd.concat(
        [src_ips, dst_ips]
    ).value_counts()


    print("\n===== ENDPOINTS =====")

    for ip, count in all_ips.items():

        print(
            f"{ip}: {count} occurrences"
        )


    # -----------------------------------------------------
    # Main source
    # -----------------------------------------------------

    if len(src_ips) > 0:

        main_source = (
            src_ips.value_counts()
            .index[0]
        )

    else:

        main_source = None


    # -----------------------------------------------------
    # Sent / received bytes
    # -----------------------------------------------------

    if main_source is not None:

        bytes_sent = df.loc[
            df["ip.src"].astype(str)
            == main_source,
            "frame.len"
        ].sum()

        bytes_received = df.loc[
            df["ip.dst"].astype(str)
            == main_source,
            "frame.len"
        ].sum()

    else:

        bytes_sent = 0
        bytes_received = 0


    # -----------------------------------------------------
    # TCP / UDP connections
    # -----------------------------------------------------

    tcp_df = df[
        df["ip.proto"]
        .astype(str)
        .str.strip()
        == "6"
    ]

    udp_df = df[
        df["ip.proto"]
        .astype(str)
        .str.strip()
        == "17"
    ]


    def count_connections(protocol_df):

        if protocol_df.empty:
            return 0

        pairs = (
            protocol_df[
                ["ip.src", "ip.dst"]
            ]
            .dropna()
            .drop_duplicates()
        )

        return len(pairs)


    tcp_connections = count_connections(
        tcp_df
    )

    udp_connections = count_connections(
        udp_df
    )


    # -----------------------------------------------------
    # Traffic imbalance
    # -----------------------------------------------------

    if bytes_sent == 0 and bytes_received == 0:

        imbalance_ratio = 0

    elif bytes_sent == 0 or bytes_received == 0:

        imbalance_ratio = float("inf")

    else:

        imbalance_ratio = max(
            bytes_sent / bytes_received,
            bytes_received / bytes_sent
        )


    # ---------------------------------------------------------
    # Calculate additional standardized features
    # ---------------------------------------------------------

    if packet_count > 0:
        avg_packet_size = total_bytes / packet_count
    else:
        avg_packet_size = 0.0


    # ---------------------------------------------------------
    # Feature dictionary for Security Assessment Engine
    # ---------------------------------------------------------

    features = {

        "packet_count":
            int(packet_count),

        "flow_duration":
            float(flow_duration),

        "bytes_sent":
            int(bytes_sent),

        "bytes_received":
            int(bytes_received),

        "avg_packet_size":
            float(avg_packet_size),

        "packets_per_second":
            float(packets_per_second),

        "bytes_per_second":
            float(bytes_per_second),

        "tcp_connections":
            int(tcp_connections),

        "udp_connections":
            int(udp_connections)
    }
    # -----------------------------------------------------
    # Run Security Assessment Engine
    # -----------------------------------------------------

    engine = SecurityAssessmentEngine()

    assessment = engine.assess(
        features
    )


    # -----------------------------------------------------
    # Security Assessment
    # -----------------------------------------------------

    print("\n===== SECURITY ASSESSMENT =====")

    print(
        json.dumps(
            assessment,
            indent=4
        )
    )


    # -----------------------------------------------------
    # Engine Features
    # -----------------------------------------------------

    print("\n===== ENGINE FEATURES =====")

    for key, value in features.items():

        print(
            f"{key}: {value}"
        )


    # -----------------------------------------------------
    # Traffic Information
    # -----------------------------------------------------

    print("\n===== TRAFFIC INFORMATION =====")

    print(
        f"Packet count:       {packet_count}"
    )

    print(
        f"Total bytes:        {total_bytes:.0f}"
    )

    print(
        f"Flow duration:      {flow_duration:.6f} seconds"
    )

    print(
        f"Packets/second:     {packets_per_second:.6f}"
    )

    print(
        f"Bytes/second:       {bytes_per_second:.6f}"
    )

    print(
        f"TCP connections:    {tcp_connections}"
    )

    print(
        f"UDP connections:    {udp_connections}"
    )

    print(
        f"Main source:        {main_source}"
    )

    print(
        f"Bytes sent:         {bytes_sent:.0f}"
    )

    print(
        f"Bytes received:     {bytes_received:.0f}"
    )

    print(
        f"Traffic imbalance:  {imbalance_ratio:.6f}"
    )


finally:

    if os.path.exists(TEMP_TSV):

        os.remove(TEMP_TSV)