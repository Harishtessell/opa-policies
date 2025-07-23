package provision

import rego.v1
import data.functions

default validate_service_name := ""
## validateServiceName

validate_service_name := msg if {
  count(input.service_name) > 63
  msg :=  "Service Name is greater then 63 characters." 
} else := msg if {
  not regex.match(`^[a-z0-9_-]*$`, input.service_name)
  msg :=  "Service Name must satisfy all the constraints." 
}

default validate_backup_configuration := ""
## validateBackupConfiguration
validate_backup_configuration := msg if {
  input.bc == null
  msg := "BackupConfiguration is missing"
} else := msg if {
  not input.bc.EnableAutomatedSnapshot
  msg := ""
} else := msg if {
  input.bc.CustomPolicy == null
  msg := ""
} else := msg if {
  input.retentionInfo.Weekly > 0
  input.bc.CustomPolicy.Schedule.WeeklySchedule == null
  msg := "Weekly Schedule is required"
} else := msg if {
  input.retentionInfo.Weekly == 0
  input.bc.CustomPolicy.Schedule.WeeklySchedule != null
  msg := "Weekly Schedule is not allowed as RPO Policy does not have Weekly retention"
} else := msg if {
  input.retentionInfo.Monthly > 0
  input.bc.CustomPolicy.Schedule.MonthlySchedule == null
  msg := "Monthly Schedule is required"
} else := msg if {
  input.retentionInfo.Monthly == 0
  input.bc.CustomPolicy.Schedule.MonthlySchedule != null
  msg := "Monthly Schedule is not allowed as RPO Policy does not have Monthly retention"
} else := msg if {
  input.retentionInfo.Yearly > 0
  input.bc.CustomPolicy.Schedule.YearlySchedule == null
  msg := "Yearly schedule is required"
} else := msg if {
  input.retentionInfo.Yearly == 0
  input.bc.CustomPolicy.Schedule.YearlySchedule != null
  msg := "Yearly Schedule is not allowed as RPO Policy does not have Yearly retention"
} 
# else := msg if {
#   input.bc.CustomPolicy.Schedule.MonthlySchedule != null
#   not valid_monthly(input.bc.CustomPolicy.Schedule.MonthlySchedule)
#   msg := "Monthly schedule is invalid"
# } else := msg if {
#   input.bc.CustomPolicy.Schedule.YearlySchedule != null
#   not valid_yearly(input.bc.CustomPolicy.Schedule.YearlySchedule)
#   msg := "Yearly schedule is invalid"
# }

default validate_oracle_sid_and_version := ""
# Returns the first validation error as a string, or "" if valid
validate_oracle_sid_and_version := msg if {
  count(input.m) < 2 
  msg := "Unsupported Oracle version. Only version 19 is supported"
} else := msg if {
  not startswith(input.m, "19")
  msg := "Unsupported Oracle version. Only version 19 is supported"
} else := msg if {
  count(input.sid) < 1
  msg := "Database name must be between 1 and 8 characters long"
} else := msg if {
  count(input.sid) > 8
  msg := "Database name must be between 1 and 8 characters long"
} else := msg if {
  not regex.match(`^[A-Za-z]$`, substring(input.sid, 0, 1))
  msg := "Database name must start with a letter"
} else := msg if {
  not functions.valid_name_chars(input.sid)
  msg := "Database name can only contain letters, digits, '_', '#', or '$'"
}