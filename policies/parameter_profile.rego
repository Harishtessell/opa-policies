package parameter_profile

gb_to_bytes := 1024*1024*1024
mb_to_bytes := 1024*1024
compute_memory := input.compute_memory
os_memory_percent := data.constraints_config.os_memory_percent

# Use override if set, else fallback to configured percentage
actual_os_memory := input.os_memory_default_override if {
	is_number(input.os_memory_default_override)
 } else := (compute_memory * os_memory_percent) / 100 


available_compute_memory := (compute_memory - actual_os_memory) * gb_to_bytes

db_available_memory := input.available_memory if {
	input.existing_server
 } else := available_compute_memory

sga_max_size := input.sga_max_size * gb_to_bytes
sga_max_size_lower_bound := 1 * gb_to_bytes
pga_aggregate_limit := input.pga_aggregate_limit * gb_to_bytes
pga_aggregate_limit_lower_bound := 3 * gb_to_bytes
pga_aggregate_target := input.pga_aggregate_target * gb_to_bytes
pga_aggregate_target_lower_bound := 1.5 * gb_to_bytes
sga_target := input.sga_target * gb_to_bytes
processes := input.processes
processes_upper_bound := 3 * mb_to_bytes
sessions := input.sessions
transactions := input.transactions

# sga_max_size constraints
deny contains msg if {
	sga_max_size < sga_max_size_lower_bound
	msg := "sga_max_size must be >= 1 GB"
}

deny contains msg if {
	sga_max_size > db_available_memory * 0.7
	msg := sprintf("sga_max_size must be <= %v GB (70%% of db_available_memory)", [db_available_memory * 0.7 / gb_to_bytes])
}

# pga_aggregate_limit constraints
deny contains msg if {
	pga_aggregate_limit < max([sga_max_size * 0.4, pga_aggregate_limit_lower_bound])
	msg := sprintf("pga_aggregate_limit must be >= %v GB (max of 40%% * sga_max_size, 3Mb)", [max([sga_max_size * 0.4 / mb_to_bytes, 3])])
}

deny contains msg if {
	sga_max_size + pga_aggregate_limit > db_available_memory
	msg := sprintf("sga_max_size + pga_aggregate_limit must be <= %v GB (db_available_memory)", [db_available_memory / gb_to_bytes])
}

# pga_aggregate_target constraints
deny contains msg if {
	pga_aggregate_target < pga_aggregate_target_lower_bound
	msg := "pga_aggregate_target must be >= 3Gb"
}

deny contains msg if {
	pga_aggregate_target > pga_aggregate_limit / 2
	msg := sprintf("pga_aggregate_target must be <= %v GB (pga_aggregate_limit / 2)", [pga_aggregate_limit / (2 * gb_to_bytes)])
}

# sga_target constraints
deny contains msg if {
	sga_target < sga_max_size_lower_bound
	msg := "sga_target must be >= 1Gb"
}

deny contains msg if {
	sga_target > sga_max_size
	msg := sprintf("sga_target must be <= %v GB (sga_max_size)", [sga_max_size/gb_to_bytes])
}

# processes constraints
deny contains msg if {
	processes < 300
	msg := "processes must be >= 300"
}

deny contains msg if {
	processes > pga_aggregate_limit / processes_upper_bound
	msg := sprintf("processes must be <=%v  (pga_aggregate_limit / 3Mb)", [pga_aggregate_limit / processes_upper_bound])
}

# sessions constraints
deny contains msg if {
	sessions < (1.5 * processes) + 50
	msg := sprintf("sessions must be >= %v (1.5 * processes + 50)", [(1.5 * processes) + 50])
}

deny contains msg if {
	sessions > ((1.5 * processes) + 50) * 2
	msg := sprintf("sessions must be <= %v ((1.5 * processes + 50) * 2)", [((1.5 * processes) + 50) * 2])
}

# transactions constraints
deny contains msg if {
	transactions < (1.1 * sessions) + 50
	msg := sprintf("transactions must be >= %v (1.1 * sessions + 50)", [(1.1 * sessions) + 50])
}

deny contains msg if {
	transactions > ((1.1 * sessions) + 50) * 2
	msg := sprintf("transactions must be <= %v ((1.1 * sessions + 50) * 2)", [((1.1 * sessions) + 50) * 2])
}

default  valid := false
valid if count(deny) == 0

result := {
  "valid": valid,
  "deny": deny
}
