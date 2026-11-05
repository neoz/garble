package ctrlflow

import (
	"fmt"
	"go/ast"
	"go/token"
	"math"
	mathrand "math/rand"
	"strconv"
	"testing"

	"github.com/go-quicktest/qt"
)

// evalInt evaluates the integer expressions built by opaquePredicates with
// the wrapping semantics of a 64-bit Go int.
func evalInt(t *testing.T, e ast.Expr, vars map[string]int64) int64 {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return evalInt(t, e.X, vars)
	case *ast.Ident:
		v, ok := vars[e.Name]
		if !ok {
			t.Fatalf("unknown variable %s", e.Name)
		}
		return v
	case *ast.BasicLit:
		v, err := strconv.ParseInt(e.Value, 0, 64)
		qt.Assert(t, qt.IsNil(err))
		return v
	case *ast.UnaryExpr:
		x := evalInt(t, e.X, vars)
		switch e.Op {
		case token.XOR:
			return ^x
		case token.SUB:
			return -x
		}
	case *ast.BinaryExpr:
		x, y := evalInt(t, e.X, vars), evalInt(t, e.Y, vars)
		switch e.Op {
		case token.ADD:
			return x + y
		case token.SUB:
			return x - y
		case token.MUL:
			return x * y
		case token.AND:
			return x & y
		case token.OR:
			return x | y
		case token.XOR:
			return x ^ y
		case token.AND_NOT:
			return x &^ y
		}
	}
	t.Fatalf("unsupported expression %#v", e)
	return 0
}

func evalBool(t *testing.T, e ast.Expr, vars map[string]int64) bool {
	b := e.(*ast.BinaryExpr)
	x, y := evalInt(t, b.X, vars), evalInt(t, b.Y, vars)
	switch b.Op {
	case token.EQL:
		return x == y
	case token.NEQ:
		return x != y
	case token.LSS:
		return x < y
	case token.LEQ:
		return x <= y
	case token.GTR:
		return x > y
	case token.GEQ:
		return x >= y
	}
	t.Fatalf("unsupported comparison %s", b.Op)
	return false
}

func TestOpaquePredicates(t *testing.T) {
	rnd := mathrand.New(mathrand.NewSource(1))
	opaque, _ := newOpaquePredicates(rnd)

	edgeValues := []int64{0, 1, -1, 2, -2, 3, 7, math.MaxInt64, math.MinInt64, math.MaxInt32, math.MinInt32}
	randomValue := func() int64 {
		if rnd.Intn(4) == 0 {
			return edgeValues[rnd.Intn(len(edgeValues))]
		}
		return int64(rnd.Uint64())
	}

	for i := range 20000 {
		want := i%2 == 0
		pred := opaque.Predicate(want)
		vars := make(map[string]int64)
		for _, name := range opaque.vars {
			vars[name] = randomValue()
		}
		if got := evalBool(t, pred, vars); got != want {
			t.Fatalf("predicate %s is %v with %v, want %v", fmt.Sprint(pred), got, vars, want)
		}
	}
}
