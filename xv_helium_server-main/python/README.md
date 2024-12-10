# Fragmentation Scenario Generation

Why is there Python here? To generate tests! There's nothing quite like `scapy`
for making packets, so we use it to generate fragmentation tests.

## How does this work?

If and only if you wish to generate fragmentation tests, execute the commands
with this directory as your current working directory:

```bash
python3 -m venv venv
source venv/bin/activate
pip install --pre 'scapy[complete]'
python3 frag_scenario_main.py > output/frag_scenario.h

# Once you've verified it
cp output/frag_scenario.h ../test/support/frag_scenario.h
```

## Wait I don't want to run python...

Then don't! These fragmentation scenarios are checked into the codebase and are
NOT currently run by CI, so if you don't take action, then they stay as they are.
