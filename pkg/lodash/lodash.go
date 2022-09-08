package lodash

import "golang.org/x/exp/constraints"

type Calculater interface {
	constraints.Integer | constraints.Float | constraints.Complex
}

func Sum[T Calculater](arr []T) T {
	var sum T
	for _, n := range arr {
		sum += n
	}
	return sum
}
