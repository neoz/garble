// Copyright (c) 2026, The Garble Authors.
// See LICENSE for licensing information.

package literals

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
)

var posType = reflect.TypeFor[token.Pos]()

// parseDecl parses a single generated top-level declaration.
func parseDecl(format string, args ...any) ast.Decl {
	src := "package p\n" + fmt.Sprintf(format, args...) + "\n"
	file, err := parser.ParseFile(token.NewFileSet(), "", src, parser.SkipObjectResolution)
	if err != nil {
		panic(fmt.Sprintf("invalid generated code: %v\n%s", err, src))
	}
	decl := file.Decls[0]
	clearPos(decl)
	return decl
}

// parseStmts parses generated statements, as if they were a function body.
func parseStmts(format string, args ...any) []ast.Stmt {
	decl := parseDecl("func _() {\n"+format+"\n}", args...)
	return decl.(*ast.FuncDecl).Body.List
}

// clearPos zeroes every position under node. The positions of parsed nodes
// belong to a throwaway FileSet, and go/printer would misplace comments and
// line breaks if they leaked into the file being obfuscated.
func clearPos(node ast.Node) {
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		v := reflect.ValueOf(n).Elem()
		for i := range v.NumField() {
			if f := v.Field(i); f.Type() == posType {
				f.SetInt(0)
			}
		}
		return true
	})
}
