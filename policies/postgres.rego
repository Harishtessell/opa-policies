package postgres

import rego.v1
import data.functions

## validateServiceName

default validate_service_name := ""
validate_service_name := msg if {
  count(input.service_name) > 63
  msg :=  "Service Name is greater then 63 characters." 
} else := msg if {
  not functions.lowercase_alphanumeric_underscore_hyphen(input.service_name)
  msg :=  "Service Name should contain lowercase, numbers, hyphen and underscores only." 
}

# validatePostgresVersion

default validate_version := ""
validate_version := msg if {
  count(input.major_version) < 2 
  msg := "Unsupported Postgres version. Only version 19 is supported"
} else := msg if {
  not startswith(input.major_version, "19")
  msg := "Unsupported Postgres version. Only version 19 is supported"
}

## validateDatabaseName

default validate_database_name := ""
validate_database_name := msg if {
  not input.dbname
  msg:= "Database name not found"
} else := msg if {
  upper(input.dbname) in data.postgres_prohibited_names
  msg:="Database name not permitted (cannot be a keyword or reserved word)"
} else := msg if {
  not count(input.dbname)<64
  msg:="Database name should be at max 63 characters long"
} else := msg if {
  not functions.start_with_lowercase_or_underscore(input.dbname)
  msg:= "Database name should start with a lowercase alphabet or underscore"
} else := msg if {
  not functions.alphanumeric_or_underscore(input.dbname)
  msg:= "Database name can contain only lowercase,uppercase alphabets,numbers and underscore"
}

## validateUsername

default validate_username := ""
validate_username := msg if {
  not input.username
  msg:= "Username not found"
} else := msg if {
  not functions.start_with_lowercase_or_underscore(input.username)
  msg:= "Username should start with a lowercase or underscore only"
} else := msg if {
  not functions.lowercase_alphanumeric_or_underscore(input.username)
  msg:= "Username should contain lowercase,numbers and underscores only"
} else := msg if {
  not count(input.username)<32
  msg:="Username should be at max 32 characters long"
}

## validatePassword

default validate_password := ""
validate_password := msg if {
  not input.password
    msg:= "Password not found"
} else := msg if {
   not count(input.password) >= 9
    msg:= "Password should be atleast 9 characters long"
} else := msg if {
  not count(input.password) <= 256
    msg:= "Password should have at max 256 characters"
} else := msg if {
  not functions.postgres_password_regex(input.password)
    msg:= "Password can contain alphanumeric characters and special characters from the set (!#$%^&*) only"
}