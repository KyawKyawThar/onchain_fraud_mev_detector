-- Reverse of 20260702073556_simulation_stores: drop the simulation OLTP tables.
-- Indexes are dropped with their table.
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS sim_jobs;
