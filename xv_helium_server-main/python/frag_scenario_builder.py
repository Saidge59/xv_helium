from scapy.all import *

import frag_scenario_templates as templates

class FragScenarioBuilder:
  def __init__(self):
    self._output_str = ""
    self._create_calls = []

  def add_scenario(self, scenario_name, packet, helium_fragsize):
    original_pkt_name = "{}_original".format(scenario_name);

    self._output_str += templates.pkt_declaration(original_pkt_name, packet)

    frag_pkt_names = []

    # Why '- 16'?
    # Helium frag size is the whole packet, while SCAPY doesn't include the header
    frag_pkts = fragment(packet, fragsize=helium_fragsize - 16)
    frag_counter = 0
    for frag_count, frag_pkt in enumerate(frag_pkts):
      frag_pkt_name = "{}_fragment_{}".format(scenario_name, frag_count)
      frag_pkt_names.append(frag_pkt_name)
      self._output_str += templates.pkt_declaration(frag_pkt_name, frag_pkt)

    self._create_calls.append(templates.create_call(scenario_name, helium_fragsize, original_pkt_name, frag_pkt_names))

  def print(self):
    # We could do more stuff here, but let's not overbake the cookie yet
    print(templates.prelude())

    print(self._output_str)

    # Why reversed? In the C code these are pushed and popped defacto on a stack,
    # so in order to get the intuitive behaviour of
    # "the first test listed is the first test run" we reverse the list here
    print(templates.create_macro(reversed(self._create_calls)))

    print(templates.postlude())
