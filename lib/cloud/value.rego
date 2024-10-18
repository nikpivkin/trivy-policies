# METADATA
# custom:
#   library: true
package lib.cloud.value

import rego.v1

is_unresolvable(val) if val.unresolvable

# string

is_empty(val) := false if {
	is_unresolvable(val)
} else := val.value == ""

starts_with(val, s) := false if {
	is_unresolvable(val)
} else := startswith(val.value, s)

ends_with(val, s) := false if {
	is_unresolvable(val)
} else := endswith(val.value, s)

string_contains(val, s) := false if {
	is_unresolvable(val)
} else := contains(val.value, s)

# int

less_than(val, other) := false if {
	is_unresolvable(val)
} else := val.value < other

greater_than(val, other) := false if {
	is_unresolvable(val)
} else := val.value > other

# bool

is_true(val) := false if {
	is_unresolvable(val)
} else := val.value == true

is_false(val) := false if {
	is_unresolvable(val)
} else := val.value == false

# common

is_equal(val, raw) := false if {
	is_unresolvable(val)
} else := val.value == raw
