// Copyright (c) 2026, The Garble Authors.
// See LICENSE for licensing information.

package literals

import (
	"go/ast"
	"go/token"
	mathrand "math/rand"

	ah "mvdan.cc/garble/internal/asthelper"
)

// keyMixer is a per-file function which derives external key values at run
// time, so that the keys passed to a decoder appear nowhere in the binary as
// constants. Recovering a literal then requires running the caller's code
// too, not just reading the decoder and its arguments.
type keyMixer struct {
	name    string
	rounds  int
	a, b, c int
	mul     uint64
	add     uint64
}

func newKeyMixer(rand *mathrand.Rand, name string) *keyMixer {
	return &keyMixer{
		name:   name,
		rounds: 3 + rand.Intn(6),
		a:      1 + rand.Intn(31),
		b:      1 + rand.Intn(31),
		c:      1 + rand.Intn(31),
		mul:    rand.Uint64() | 1,
		add:    rand.Uint64(),
	}
}

func (m *keyMixer) eval(s uint64) uint64 {
	for i := range m.rounds {
		s ^= s << m.a
		s ^= s >> m.b
		s ^= s << m.c
		s = s*m.mul + uint64(i)*m.add
	}
	return s
}

func (m *keyMixer) decl() ast.Decl {
	return parseDecl(`func %s(s uint64) uint64 {
	for i := 0; i < %d; i++ {
		s ^= s << %d
		s ^= s >> %d
		s ^= s << %d
		s = s*%d + uint64(i)*%d
	}
	return s
}`, m.name, m.rounds, m.a, m.b, m.c, m.mul, m.add)
}

// mixedKeyExpr returns an expression like
//
//	uint16(proxy.path.mixer(<seed>) ^ <mask>)
//
// which evaluates to key.value at run time. The mixer is reached through the
// proxy dispatcher, so the call is indirect and cannot be inlined or folded.
func (r *obfRand) mixedKeyExpr(key *externalKey) ast.Expr {
	if r.mixer == nil {
		r.mixer = newKeyMixer(r.rnd, r.nextLiftedFuncName("literalKeyMixer"))
		r.liftedFuncs = append(r.liftedFuncs, r.mixer.decl())
	}
	seed := r.rnd.Uint64()
	mask := r.mixer.eval(seed) ^ key.value
	fn := r.proxyDispatcher.HideValue(ast.NewIdent(r.mixer.name), &ast.FuncType{
		Params:  &ast.FieldList{List: []*ast.Field{{Type: ast.NewIdent("uint64")}}},
		Results: &ast.FieldList{List: []*ast.Field{{Type: ast.NewIdent("uint64")}}},
	})
	call := ah.CallExpr(fn, ah.UintLit(seed))
	return ah.CallExprByName(key.typ, ah.BinaryExpr(call, token.XOR, ah.UintLit(mask)))
}
