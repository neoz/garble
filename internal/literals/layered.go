// Copyright (c) 2026, The Garble Authors.
// See LICENSE for licensing information.

package literals

import (
	"fmt"
	"go/ast"
	"go/token"
	mathrand "math/rand"
)

const (
	minLayers = 2
	maxLayers = 4
)

// layered encrypts data with a random stack of reversible byte transforms,
// each with its own random parameters. The decoder undoes them in reverse
// order. The generated code does not grow with the data, so this obfuscator
// is also cheap for large literals.
type layered struct{}

// check that the obfuscator interface is implemented
var _ obfuscator = layered{}

// layer is a reversible transform: encrypt applies it to data in place, and
// decodeSrc holds the Go statements which undo it on a variable named data.
type layer struct {
	encrypt   func(data []byte)
	decodeSrc string
}

var layerKinds = []func(rand *mathrand.Rand, n int, extKeys []*externalKey) layer{
	affineLayer,
	rotateLayer,
	chainLayer,
	nibbleSboxLayer,
	strideLayer,
	extKeyLayer,
}

// affineLayer: c = p*m + i*a + b, with m odd so that it is invertible mod 256.
func affineLayer(rand *mathrand.Rand, _ int, _ []*externalKey) layer {
	m, a, b := byte(rand.Intn(256))|1, byte(rand.Intn(256)), byte(rand.Intn(256))
	minv := m // Newton's iteration doubles the correct low bits each round.
	for range 3 {
		minv *= 2 - m*minv
	}
	return layer{
		encrypt: func(data []byte) {
			for i := range data {
				data[i] = data[i]*m + byte(i)*a + b
			}
		},
		decodeSrc: fmt.Sprintf(`for i := range data {
	data[i] = (data[i] - byte(i)*%d - %d) * %d
}`, a, b, minv),
	}
}

// rotateLayer rotates each byte left by an amount which depends on its index.
func rotateLayer(rand *mathrand.Rand, _ int, _ []*externalKey) layer {
	s, t := rand.Intn(8), rand.Intn(8)
	return layer{
		encrypt: func(data []byte) {
			for i := range data {
				r := (i*s + t) & 7
				data[i] = data[i]<<r | data[i]>>(8-r)
			}
		},
		decodeSrc: fmt.Sprintf(`for i := range data {
	r := uint(i*%d+%d) & 7
	data[i] = data[i]>>r | data[i]<<(8-r)
}`, s, t),
	}
}

// chainLayer combines each byte with its already encrypted neighbour, in a
// random direction and with a random operator.
func chainLayer(rand *mathrand.Rand, n int, _ []*externalKey) layer {
	op := randOperator(rand)
	iv := byte(rand.Intn(256))
	inv := map[token.Token]string{token.XOR: "^=", token.ADD: "-=", token.SUB: "+="}[op]
	if rand.Intn(2) == 0 {
		return layer{
			encrypt: func(data []byte) {
				data[0] = evalOperator(op, data[0], iv)
				for i := 1; i < len(data); i++ {
					data[i] = evalOperator(op, data[i], data[i-1])
				}
			},
			decodeSrc: fmt.Sprintf(`for i := %d; i > 0; i-- {
	data[i] %s data[i-1]
}
data[0] %s %d`, n-1, inv, inv, iv),
		}
	}
	return layer{
		encrypt: func(data []byte) {
			data[n-1] = evalOperator(op, data[n-1], iv)
			for i := n - 2; i >= 0; i-- {
				data[i] = evalOperator(op, data[i], data[i+1])
			}
		},
		decodeSrc: fmt.Sprintf(`for i := 0; i < %d; i++ {
	data[i] %s data[i+1]
}
data[%d] %s %d`, n-1, inv, n-1, inv, iv),
	}
}

// nibbleSboxLayer substitutes the high and low nibbles of each byte through
// two random 16-entry permutations.
func nibbleSboxLayer(rand *mathrand.Rand, _ int, _ []*externalKey) layer {
	hi, lo := rand.Perm(16), rand.Perm(16)
	hiInv, loInv := make([]byte, 16), make([]byte, 16)
	for i := range 16 {
		hiInv[hi[i]], loInv[lo[i]] = byte(i), byte(i)
	}
	return layer{
		encrypt: func(data []byte) {
			for i, b := range data {
				data[i] = byte(hi[b>>4])<<4 | byte(lo[b&15])
			}
		},
		decodeSrc: fmt.Sprintf(`hi := [16]byte{%s}
lo := [16]byte{%s}
for i, b := range data {
	data[i] = hi[b>>4]<<4 | lo[b&15]
}`, byteList(hiInv), byteList(loInv)),
	}
}

// strideLayer permutes the bytes: byte i moves to (i*s+o) mod n, with s
// coprime to n.
func strideLayer(rand *mathrand.Rand, n int, _ []*externalKey) layer {
	s := 1
	if n > 2 {
		for s = 1 + rand.Intn(n-1); gcd(s, n) != 1; s = 1 + rand.Intn(n-1) {
		}
	}
	o := rand.Intn(n)
	return layer{
		encrypt: func(data []byte) {
			out := make([]byte, n)
			for i, b := range data {
				out[(i*s+o)%n] = b
			}
			copy(data, out)
		},
		decodeSrc: fmt.Sprintf(`tmp := make([]byte, %d)
for i := range tmp {
	tmp[i] = data[(i*%d+%d)%%%d]
}
copy(data, tmp)`, n, s, o, n),
	}
}

// extKeyLayer XORs each byte with a byte of an external key, chosen by index,
// so that the key is needed throughout decoding and not only up front.
func extKeyLayer(rand *mathrand.Rand, _ int, extKeys []*externalKey) layer {
	key := extKeys[rand.Intn(len(extKeys))]
	key.AddRef()
	width := key.bits / 8
	o, m := rand.Intn(width), rand.Intn(256)
	return layer{
		encrypt: func(data []byte) {
			for i := range data {
				data[i] ^= byte(key.value>>((i+o)%width*8)) ^ byte(i*m)
			}
		},
		decodeSrc: fmt.Sprintf(`for i := range data {
	data[i] ^= byte(%s>>(uint(i+%d)%%%d*8)) ^ byte(i*%d)
}`, key.name, o, width, m),
	}
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func byteList(b []byte) string {
	s := ""
	for i, v := range b {
		if i > 0 {
			s += ", "
		}
		s += fmt.Sprint(v)
	}
	return s
}

func (layered) obfuscate(rand *mathrand.Rand, data []byte, extKeys []*externalKey) *ast.BlockStmt {
	layers := make([]layer, minLayers+rand.Intn(maxLayers-minLayers+1))
	for i := range layers {
		layers[i] = layerKinds[rand.Intn(len(layerKinds))](rand, len(data), extKeys)
		layers[i].encrypt(data)
	}

	stmts := []ast.Stmt{
		&ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent("data")},
			Tok: token.DEFINE,
			Rhs: []ast.Expr{dataToByteSliceWithExtKeys(rand, data, extKeys)},
		},
	}
	// Each decode step gets its own block, so that their locals do not clash.
	for i := len(layers) - 1; i >= 0; i-- {
		stmts = append(stmts, &ast.BlockStmt{List: parseStmts("%s", layers[i].decodeSrc)})
	}
	return &ast.BlockStmt{List: stmts}
}
