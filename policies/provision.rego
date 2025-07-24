package provision

import rego.v1
import data.functions

## validateServiceName

default validate_service_name := ""
validate_service_name := msg if {
  count(input.service_name) > 63
  msg :=  "Service Name is greater then 63 characters." 
} else := msg if {
  not regex.match(`^[a-z0-9_-]*$`, input.service_name)
  msg :=  "Service Name must satisfy all the constraints." 
}

## validateBackupConfiguration

default validate_backup_configuration := ""
validate_backup_configuration := msg if {
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

# validateOracleSidAndVersion

default validate_oracle_sid_and_version := ""
validate_oracle_sid_and_version := msg if {
  count(input.major_version) < 2 
  msg := "Unsupported Oracle version. Only version 19 is supported"
} else := msg if {
  not startswith(input.major_version, "19")
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