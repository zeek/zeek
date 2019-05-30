## Returns the first n number of items from a vector
##
## v: a vector
## n: the length of the tail
##
## Returns: a shorter vector
function vector_remove_from_head(v: vector of any, n: count): vector of any {
  local v2 = vector();
  local index: count;

  for (index in v) {
    if (index <= n - 1) {
      next;
    }
    v2 += v[index];
  }
  return v2;
}

## Returns the last n number of items from a vector
##
## v: a vector
## n: the length of the head
##
## Returns: a shorter vector
function vector_remove_from_tail(v: vector of any, n: count): vector of any {
  local v2 = vector();
  local index: count;
  local l = |v|;

  # This assumes |v| is longer than n
  for (index in v) {
    if (index < l - n) {
      v2 += v[index];
    }
  }
  return v2;
}
