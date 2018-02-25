class Hash(K, V)

  def sort
    to_a.sort.to_h
  end

  # Returns a tuple populated with the elements at the given indexes. Invalid indexes are ignored.
  def values_at?(*indexes : K)
    indexes.map { |index| self[index]? }
  end

end
