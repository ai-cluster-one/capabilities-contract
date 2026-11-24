"""The core's sixth step: a node says how much of its CPU is in use.

It adds `node_states.cpu_percent`, the share of the node's whole allotted CPU
in use over the moments before its row was written: every core it may run on
busy is 100, and inside a container the cgroup's quota is the whole. A node
that cannot say writes it null, and a row a node wrote before the step stays
null until that node writes again.

The step adds one nullable column and changes no row, so it is a minor step
(core 4.3): it is applied wherever the core is at major 4, outside the store
upgrade, and a release that knows core 4.2 reads a store at 4.3 as a newer
minor. Never edit the step once released: a store holds its checksum.
"""

from __future__ import annotations

STEP_ID = "0044-node-cpu-percent"
MAJOR, MINOR = 4, 3

STEP_SQL = """\
ALTER TABLE node_states ADD COLUMN cpu_percent double precision
 CONSTRAINT node_states_cpu_percent_check CHECK (cpu_percent >= 0 AND cpu_percent <= 100);
COMMENT ON COLUMN node_states.cpu_percent IS 'The share of the node''s whole allotted CPU \
in use over the moments before reported_at, 0 to 100: every core the node may run on busy \
is 100, and inside a container its cgroup''s quota is the whole. Null where the node does \
not say, and on a row written before the store kept it (core 4.3).';"""
