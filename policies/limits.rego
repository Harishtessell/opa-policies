package limits

default res := false

res if {
  input.amount <= 2*data.limits.max
}
