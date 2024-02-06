package calc

import (
	"math/big"

	"golang.org/x/exp/constraints"
)

type Number interface {
	constraints.Integer | constraints.Float
}

func MaxBig(x, y *big.Int) *big.Int {
	if x.Cmp(y) < 0 {
		return y
	} else {
		return x
	}
}

func MinBig(x, y *big.Int) *big.Int {
	if x.Cmp(y) > 0 {
		return y
	} else {
		return x
	}
}

func Max[T Number](x, y T) T {
	if x > y {
		return x
	} else {
		return y
	}
}

func Min[T Number](x, y T) T {
	if x < y {
		return x
	} else {
		return y
	}
}
