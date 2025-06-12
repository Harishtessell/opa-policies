package provision

valid_pattern := "^[a-z0-9_-]*$"

default deny := "no"

deny := msg if {
  count(input.service_name) > 63
  msg :=  "Service Name is greater then 63 characters." 
} else := msg if {
  not regex.match(valid_pattern, input.service_name)
  msg :=  "Service Name must satisfy all the constraints." 
}
