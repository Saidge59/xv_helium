from scapy.all import *
import sys

import frag_scenario_templates as templates
from frag_scenario_builder import FragScenarioBuilder

if __name__ == "__main__":
    builder = FragScenarioBuilder()

    payload = "A"*4 + "B"*5
    packet = IP(dst="173.63.1.2",src="200.123.21.212",id=12345)/UDP(sport=1500,dport=1501)/payload
    builder.add_scenario("simple_packet", packet, 500)

    payload = "A"*400 + "B" * 400
    packet = IP(dst="173.63.1.2",src="200.123.21.212",id=12345)/UDP(sport=1500,dport=1501)/payload
    builder.add_scenario("frag_packet", packet, 500)

    payload = b"\xFF" * 1000
    packet = IP(dst="173.63.1.2",src="200.123.21.212",id=12345)/UDP(sport=1500,dport=1501)/payload
    builder.add_scenario("high_packet", packet, 500)

    builder.print()
