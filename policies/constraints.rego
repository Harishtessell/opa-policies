package constraints

compute_memory := input.compute_memory
os_memory_percent := data.constraints_config.os_memory_percent

# Use override if set, else fallback to configured percentage
actual_os_memory := input.os_memory_default_override if {
	input.os_memory_default_override != null
}

actual_os_memory := (compute_memory * os_memory_percent) / 100 if {
	not input.os_memory_default_override
}

available_compute_memory := compute_memory - actual_os_memory
db_total_allotted_memory := input.db_total_allotted_memory
db_available_memory := available_compute_memory - db_total_allotted_memory

sga_max_size := input.sga_max_size
pga_aggregate_limit := input.pga_aggregate_limit
pga_aggregate_target := input.pga_aggregate_target
sga_target := input.sga_target
processes := input.processes
sessions := input.sessions
transactions := input.transactions

# SMS constraints
sms_min := 1
sms_max := db_available_memory * 0.7
sms_log := sprintf("sms must be >= %.2f and <= %.2f", [sms_min, sms_max])
alog := sprintf("sga_max_size + pga_aggregate_limit must be <= %v (db_available_memory)", [db_available_memory])
# PAL constraints
pal_min := max([sga_max_size * 0.4, 3])
pal_max := db_available_memory - sga_max_size
pal_log := sprintf("pal must be >= %.2f and <= %.2f (to keep sms + pal <= dbam)", [pal_min, pal_max])

# PAT constraints
pat_min := 1.5
pat_max := pga_aggregate_limit / 2
pat_log := sprintf("pat must be >= %.2f and <= %.2f", [pat_min, pat_max])

# ST constraints
st_min := 1
st_log := sprintf("st must be >= %.2f and <= %.2f", [st_min, sga_max_size])

# P constraints
p_min := 300
p_max := pga_aggregate_limit * 1024 / 3
p_log := sprintf("p must be >= %.2f and <= %.2f", [p_min, p_max])

# S constraints
s_min := 1.5 * processes + 50
s_max := s_min * 2
s_log := sprintf("s must be >= %.2f and <= %.2f", [s_min, s_max])

# T constraints
t_min := 1.1 * sessions + 50
t_max := t_min * 2
t_log := sprintf("t must be >= %.2f and <= %.2f", [t_min, t_max])

log:=true

deny contains msg if {
	log
	msg:=concat("\n",[sms_log,alog,pal_log,pat_log,st_log,p_log,s_log,t_log])
}

# sga_max_size constraints
deny contains msg if {
	sga_max_size < 1
	msg := "sga_max_size must be >= 1 GB"
}

deny contains msg if {
	sga_max_size > db_available_memory * 0.7
	msg := sprintf("sga_max_size must be <= %v (70%% of db_available_memory)", [db_available_memory * 0.7])
}

# pga_aggregate_limit constraints
deny contains msg if {
	pga_aggregate_limit < max([sga_max_size * 0.4, 3])
	msg := sprintf("pga_aggregate_limit must be >= %v (max of 40%% * sga_max_size, 3)", [max([sga_max_size * 0.4, 3])])
}

deny contains msg if {
	sga_max_size + pga_aggregate_limit > db_available_memory
	msg := sprintf("sga_max_size + pga_aggregate_limit must be <= %v (db_available_memory)", [db_available_memory])
}

# pga_aggregate_target constraints
deny contains msg if {
	pga_aggregate_target < 1.5
	msg := "pga_aggregate_target must be >= 1.5 GB"
}

deny contains msg if {
	pga_aggregate_target > pga_aggregate_limit / 2
	msg := sprintf("pga_aggregate_target must be <= %v (pga_aggregate_limit/2)", [pga_aggregate_limit / 2])
}

# sga_target constraints
deny contains msg if {
	sga_target < 1
	msg := "sga_target must be >= 1 GB"
}

deny contains msg if {
	sga_target > sga_max_size
	msg := sprintf("sga_target must be <= %v (sga_max_size)", [sga_max_size])
}

# processes constraints
deny contains msg if {
	processes < 300
	msg := "processes must be >= 300"
}

deny contains msg if {
	processes > pga_aggregate_limit * 1024 / 3
	msg := sprintf("processes must be <=%v  (pga_aggregate_limit / 3)", [pga_aggregate_limit * 1024 / 3])
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
