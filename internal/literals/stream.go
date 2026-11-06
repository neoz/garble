// Copyright (c) 2026, The Garble Authors.
// See LICENSE for licensing information.

package literals

import (
	"fmt"
	"go/ast"
	"go/token"
	mathrand "math/rand"
)

// stream encrypts data with a keystream from a small random PRNG, seeded by
// an external key and fed back with each ciphertext byte, so that every byte
// depends on all the bytes decoded before it. The PRNG kind, its constants,
// the byte operator, a bit rotation, and the direction all vary per literal.
type stream struct{}

// check that the obfuscator interface is implemented
var _ obfuscator = stream{}

type streamPRNG struct {
	kind    int
	x, y, z uint32
}

func randStreamPRNG(rand *mathrand.Rand) streamPRNG {
	return streamPRNG{
		kind: rand.Intn(3),
		x:    rand.Uint32(),
		y:    rand.Uint32(),
		z:    rand.Uint32(),
	}
}

func (p streamPRNG) shifts() (a, b, c uint32) {
	return 1 + p.x%15, 1 + p.y%20, 1 + p.z%15
}

func (p streamPRNG) next(s uint32) uint32 {
	switch p.kind {
	case 0: // xorshift
		a, b, c := p.shifts()
		s ^= s << a
		s ^= s >> b
		s ^= s << c
	case 1: // LCG
		s = s*(p.x|1) + (p.y | 1)
	default: // multiply-xorshift
		s = (s^s>>(1+p.z%31))*(p.x|1) + p.y
	}
	return s
}

func (p streamPRNG) nextSrc() string {
	switch p.kind {
	case 0:
		a, b, c := p.shifts()
		return fmt.Sprintf("state ^= state << %d\nstate ^= state >> %d\nstate ^= state << %d", a, b, c)
	case 1:
		return fmt.Sprintf("state = state*%d + %d", p.x|1, p.y|1)
	default:
		return fmt.Sprintf("state = (state ^ state>>%d)*%d + %d", 1+p.z%31, p.x|1, p.y)
	}
}

func rotl8(b byte, r int) byte { return b<<r | b>>(8-r) }

func (stream) obfuscate(rand *mathrand.Rand, data []byte, extKeys []*externalKey) *ast.BlockStmt {
	key := extKeys[rand.Intn(len(extKeys))]
	key.AddRef()

	prng := randStreamPRNG(rand)
	seed := rand.Uint32()
	op := randOperator(rand)
	rot := 1 + rand.Intn(7)
	keyShift := rand.Intn(25)
	feedShift := rand.Intn(25)
	posMul := rand.Intn(256)
	reverse := rand.Intn(2) == 0

	state := seed ^ uint32(key.value)
	for n := range data {
		i := n
		if reverse {
			i = len(data) - 1 - n
		}
		state = prng.next(state)
		k := byte(state>>keyShift) + byte(i*posMul)
		c := rotl8(evalOperator(op, data[i], k), rot)
		data[i] = c
		state ^= uint32(c) << feedShift
	}

	loop := "for i := 0; i < len(data); i++ {"
	if reverse {
		loop = "for i := len(data) - 1; i >= 0; i-- {"
	}
	inv := map[token.Token]string{token.XOR: "^", token.ADD: "-", token.SUB: "+"}[op]

	stmts := []ast.Stmt{
		&ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent("data")},
			Tok: token.DEFINE,
			Rhs: []ast.Expr{dataToByteSliceWithExtKeys(rand, data, extKeys)},
		},
	}
	stmts = append(stmts, parseStmts(`state := uint32(%d) ^ uint32(%s)
%s
	%s
	c := data[i]
	data[i] = (c>>%d | c<<%d) %s (byte(state>>%d) + byte(i*%d))
	state ^= uint32(c) << %d
}`, seed, key.name, loop, prng.nextSrc(), rot, 8-rot, inv, keyShift, posMul, feedShift)...)
	return &ast.BlockStmt{List: stmts}
}
