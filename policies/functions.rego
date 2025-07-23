package functions
import rego.v1

round_to_2_decimals(x) := round(x * 100) / 100

# Returns true if all characters in `s` are valid
valid_name_chars(s) if {
  chars := split(s, "")
  count([c | c := chars[_]; not valid_char(c)]) == 0
}

valid_char(c) if {
  regex.match(`^[A-Za-z0-9_#$]$`, c)
}