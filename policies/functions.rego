package functions

round_to_2_decimals(x) := round(x * 100) / 100

start_with_lowercase_or_underscore(s) if {
  regex.match(`^(?:[a-z_].*)`,s)
}

alphanumeric_or_underscore(s) if {
  regex.match(`^(?:[a-zA-Z0-9_]+)$`,s)
}

lowercase_alphanumeric_or_underscore(s) if {
  regex.match(`^(?:[a-z0-9_]+)$`,s)
}

lowercase_alphanumeric_underscore_hyphen(s) if {
  regex.match(`^[a-z0-9_-]*$`,s)
}

postgres_password_regex(s) if {
  regex.match(`^[A-Za-z0-9!#$%^&*]+$`,s)
}

alphanumeric_or_special_chars(s) if {
  regex.match(`^(?:[A-Za-z0-9_#$]+)$`,s)
}