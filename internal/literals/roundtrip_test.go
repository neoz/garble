package literals_test

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	mathrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"mvdan.cc/garble/internal/literals"
)

// TestRoundTrip obfuscates many random string and []byte literals in a single
// program, so that every obfuscator and decode variant is exercised in one
// build, and checks that the program prints the original bytes.
func TestRoundTrip(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(1))
	var src, want strings.Builder
	src.WriteString("package main\n\nimport \"os\"\n\nfunc main() {\n")
	for i := range 300 {
		size := 8 + rand.Intn(250)
		if i%20 == 0 { // only cheap obfuscators are used past MaxSizeExpensive
			size = literals.MaxSizeExpensive + 1 + rand.Intn(literals.MaxSize-literals.MaxSizeExpensive)
		}
		data := make([]byte, size)
		rand.Read(data)
		fmt.Fprintf(&src, "\tos.Stdout.WriteString(%q)\n\tos.Stdout.Write(%#v)\n", data, data)
		want.Write(data)
		want.Write(data)
	}
	src.WriteString("}\n")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", src.String(), parser.SkipObjectResolution)
	qt.Assert(t, qt.IsNil(err))
	info := types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}
	conf := types.Config{Importer: importer.Default()}
	_, err = conf.Check("main", fset, []*ast.File{file}, &info)
	qt.Assert(t, qt.IsNil(err))

	file = literals.Obfuscate(rand, file, &info, nil, func(rand *mathrand.Rand, baseName string) string {
		return fmt.Sprintf("%s%d", baseName, rand.Uint64())
	})
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "main.go")
	f, err := os.Create(srcPath)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(printer.Fprint(f, fset, file)))
	qt.Assert(t, qt.IsNil(f.Close()))

	binPath := filepath.Join(dir, "main")
	out, err := exec.Command("go", "build", "-o", binPath, srcPath).CombinedOutput()
	qt.Assert(t, qt.IsNil(err), qt.Commentf("%s", out))
	out, err = exec.Command(binPath).Output()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(string(out) == want.String()), qt.Commentf("decoded output differs"))
}
