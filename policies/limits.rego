package limits

default res := false

res if {
  input.amount <= data.limits.max
}
