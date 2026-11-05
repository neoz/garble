package ctrlflow

import (
	"go/ast"
	"go/token"
	mathrand "math/rand"

	ah "mvdan.cc/garble/internal/asthelper"
)

const opaqueVarCount = 4

// opaquePredicates generates conditions whose result is fixed but cannot be
// computed at compile time: they read package-level variables that the
// compiler cannot treat as constants, because trash blocks (which never run)
// assign to them. Every identity holds modulo 2^64, so integer overflow does
// not change the result.
type opaquePredicates struct {
	vars []string
	rnd  *mathrand.Rand
}

func newOpaquePredicates(rnd *mathrand.Rand) (*opaquePredicates, ast.Decl) {
	o := &opaquePredicates{rnd: rnd}
	spec := &ast.ValueSpec{}
	for range opaqueVarCount {
		name := getRandomName(rnd)
		o.vars = append(o.vars, name)
		spec.Names = append(spec.Names, ast.NewIdent(name))
		spec.Values = append(spec.Values, ah.IntLit(int(rnd.Int31())))
	}
	return o, &ast.GenDecl{Tok: token.VAR, Specs: []ast.Spec{spec}}
}

func paren(x ast.Expr) ast.Expr { return &ast.ParenExpr{X: x} }

func bin(x ast.Expr, op token.Token, y ast.Expr) ast.Expr {
	return paren(ah.BinaryExpr(x, op, y))
}

// opaqueIdentities return two expressions and the operator for which
// "lhs op rhs" is always false; the negated operator makes it always true.
var opaqueIdentities = []func(x, y func() ast.Expr) (ast.Expr, token.Token, ast.Expr){
	// x*(x+1) is even.
	func(x, _ func() ast.Expr) (ast.Expr, token.Token, ast.Expr) {
		return bin(bin(x(), token.MUL, bin(x(), token.ADD, ah.IntLit(1))), token.AND, ah.IntLit(1)), token.NEQ, ah.IntLit(0)
	},
	// A square is 0 or 1 modulo 4.
	func(x, _ func() ast.Expr) (ast.Expr, token.Token, ast.Expr) {
		return bin(bin(x(), token.MUL, x()), token.AND, ah.IntLit(3)), token.GTR, ah.IntLit(1)
	},
	// (x*(x+1))^2 is a multiple of 4.
	func(x, _ func() ast.Expr) (ast.Expr, token.Token, ast.Expr) {
		p := func() ast.Expr { return bin(x(), token.MUL, bin(x(), token.ADD, ah.IntLit(1))) }
		return bin(bin(p(), token.MUL, p()), token.AND, ah.IntLit(3)), token.NEQ, ah.IntLit(0)
	},
	// Squares modulo 8 are 0, 1 or 4, while 7*y*y-1 modulo 8 is 3, 6 or 7.
	func(x, y func() ast.Expr) (ast.Expr, token.Token, ast.Expr) {
		return bin(x(), token.MUL, x()), token.EQL, bin(bin(bin(ah.IntLit(7), token.MUL, y()), token.MUL, y()), token.SUB, ah.IntLit(1))
	},
	// (x|y) - (x&y) == x^y
	func(x, y func() ast.Expr) (ast.Expr, token.Token, ast.Expr) {
		return bin(bin(x(), token.OR, y()), token.SUB, bin(x(), token.AND, y())), token.NEQ, bin(x(), token.XOR, y())
	},
	// (x^y) + 2*(x&y) == x+y
	func(x, y func() ast.Expr) (ast.Expr, token.Token, ast.Expr) {
		return bin(bin(x(), token.XOR, y()), token.ADD, bin(ah.IntLit(2), token.MUL, bin(x(), token.AND, y()))), token.NEQ, bin(x(), token.ADD, y())
	},
	// ^x + 1 == -x
	func(x, _ func() ast.Expr) (ast.Expr, token.Token, ast.Expr) {
		return bin(ah.UnaryExpr(token.XOR, x()), token.ADD, ah.IntLit(1)), token.NEQ, paren(ah.UnaryExpr(token.SUB, x()))
	},
	// (x&y) | (x&^y) == x
	func(x, y func() ast.Expr) (ast.Expr, token.Token, ast.Expr) {
		return bin(bin(x(), token.AND, y()), token.OR, bin(x(), token.AND_NOT, y())), token.NEQ, x()
	},
}

var negatedOp = map[token.Token]token.Token{
	token.EQL: token.NEQ,
	token.NEQ: token.EQL,
	token.GTR: token.LEQ,
}

// mirroredOp gives the operator to use after swapping the operands.
var mirroredOp = map[token.Token]token.Token{
	token.EQL: token.EQL,
	token.NEQ: token.NEQ,
	token.GTR: token.LSS,
	token.LEQ: token.GEQ,
}

// Predicate returns a boolean expression that always evaluates to value.
func (o *opaquePredicates) Predicate(value bool) ast.Expr {
	// Distinct variables, as identities like x^x are easy to simplify.
	idxs := o.rnd.Perm(len(o.vars))
	xName, yName := o.vars[idxs[0]], o.vars[idxs[1]]
	x := func() ast.Expr { return ast.NewIdent(xName) }
	y := func() ast.Expr { return ast.NewIdent(yName) }

	lhs, op, rhs := opaqueIdentities[o.rnd.Intn(len(opaqueIdentities))](x, y)
	if value {
		op = negatedOp[op]
	}
	if o.rnd.Intn(2) == 0 {
		lhs, rhs, op = rhs, lhs, mirroredOp[op]
	}
	return ah.BinaryExpr(lhs, op, rhs)
}

// Clobber returns an assignment to one of the variables read by predicates.
// It is only placed in blocks that never run; its purpose is to stop the
// compiler and static analysis from proving the variables constant.
func (o *opaquePredicates) Clobber() ast.Stmt {
	name := o.vars[o.rnd.Intn(len(o.vars))]
	other := o.vars[o.rnd.Intn(len(o.vars))]
	return ah.AssignStmt(ast.NewIdent(name), bin(bin(ast.NewIdent(other), token.MUL, ah.IntLit(int(o.rnd.Int31()|1))), token.ADD, ah.IntLit(int(o.rnd.Int31()))))
}
