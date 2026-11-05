package ctrlflow

import (
	"cmp"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	mathrand "math/rand"
	"slices"
	"strconv"

	"golang.org/x/tools/go/ssa"
	"mvdan.cc/garble/internal/ssa2ast"
)

type blockMapping struct {
	Fake, Target *ssa.BasicBlock
}

type cfgInfo struct {
	// StoreVar is the value assigned to the dispatcher state before jumping to it.
	// Hardening replaces it with an expression that evaluates to Key at run time.
	StoreVar ssa.Value
	Key      int
}

type dispatcherInfo []cfgInfo

// dispatchEntry is a state value handled by a dispatcher and the block it leads to.
type dispatchEntry struct {
	key    int
	target *ssa.BasicBlock
}

// applyFlattening redirects all ssa.Jump and ssa.If to dispatcher blocks, which jump to the real
// target selected by a state variable stored in an ssa.Phi, and shuffles all blocks.
// Every jump goes to one of dispatcherCount dispatchers, each with its own state variable and a
// randomly chosen layout. The first dispatcher is also the function entry: there its state
// variable has the zero value, which selects the original entry block.
func applyFlattening(ssaFunc *ssa.Function, dispatcherCount int, obfRand *mathrand.Rand) []dispatcherInfo {
	if len(ssaFunc.Blocks) < 3 {
		return nil
	}

	type dispatcher struct {
		phi     *ssa.Phi
		head    *ssa.BasicBlock
		entries []dispatchEntry
		info    dispatcherInfo
	}
	dispatchers := make([]*dispatcher, dispatcherCount)
	for i := range dispatchers {
		phi := &ssa.Phi{Comment: "ctrflow.phi"}
		setType(phi, types.Typ[types.Int])
		head := &ssa.BasicBlock{
			Comment: "ctrflow.entry",
			Instrs:  []ssa.Instruction{phi},
		}
		setBlockParent(head, ssaFunc)
		dispatchers[i] = &dispatcher{phi: phi, head: head}
	}
	realEntryBlock := ssaFunc.Blocks[0]
	dispatchers[0].entries = []dispatchEntry{{0, realEntryBlock}}

	// Only ssa.Jump and ssa.If have successors: ssa.Return and ssa.Panic are left as they are.
	targetCount := 0
	for _, block := range ssaFunc.Blocks {
		targetCount += len(block.Succs)
	}
	// 0 is excluded, as it selects the real entry block.
	keys := generateKeys(targetCount, []int{0}, obfRand)

	var newBlocks []*ssa.BasicBlock
	for _, block := range ssaFunc.Blocks {
		for succIdx, target := range block.Succs {
			d := dispatchers[obfRand.Intn(dispatcherCount)]
			key := keys[0]
			keys = keys[1:]

			cfg := cfgInfo{StoreVar: makeSsaInt(key), Key: key}
			d.info = append(d.info, cfg)
			d.entries = append(d.entries, dispatchEntry{key, target})

			// The fake block replaces the edge, while target.Preds keeps block:
			// the phis of target are still assigned at the end of block.
			fakeBlock := &ssa.BasicBlock{
				Comment: "ctrflow.jump",
				Instrs:  []ssa.Instruction{&ssa.Jump{}},
				Preds:   []*ssa.BasicBlock{block},
				Succs:   []*ssa.BasicBlock{d.head},
			}
			setBlockParent(fakeBlock, ssaFunc)
			block.Succs[succIdx] = fakeBlock
			d.head.Preds = append(d.head.Preds, fakeBlock)
			d.phi.Edges = append(d.phi.Edges, cfg.StoreVar)
			newBlocks = append(newBlocks, fakeBlock)
		}
	}

	var infos []dispatcherInfo
	for i, d := range dispatchers {
		if i > 0 && len(d.entries) == 0 {
			continue // no jump was assigned to this dispatcher
		}
		// The jump in head is filled in by the dispatch layout.
		d.head.Instrs = append(d.head.Instrs, &ssa.Jump{})
		var root *ssa.BasicBlock
		var blocks []*ssa.BasicBlock
		if obfRand.Intn(2) == 0 {
			root, blocks = buildChainDispatch(ssaFunc, d.phi, d.entries, obfRand)
		} else {
			root, blocks = buildTreeDispatch(ssaFunc, d.phi, d.entries, obfRand)
		}
		d.head.Succs = []*ssa.BasicBlock{root}
		root.Preds = append(root.Preds, d.head)
		newBlocks = append(newBlocks, blocks...)
		if i > 0 {
			newBlocks = append(newBlocks, d.head)
		}
		if len(d.info) > 0 {
			infos = append(infos, d.info)
		}
	}

	// ssa2ast only emits a label for blocks with predecessors, and the real entry block has none.
	// Blocks which had predecessors keep them: their phis are assigned in those.
	for _, block := range newBlocks {
		for _, succ := range block.Succs {
			if len(succ.Preds) == 0 {
				succ.Preds = append(succ.Preds, block)
			}
		}
	}

	obfuscatedBlocks := append(ssaFunc.Blocks, newBlocks...)
	obfRand.Shuffle(len(obfuscatedBlocks), func(i, j int) {
		obfuscatedBlocks[i], obfuscatedBlocks[j] = obfuscatedBlocks[j], obfuscatedBlocks[i]
	})
	ssaFunc.Blocks = append([]*ssa.BasicBlock{dispatchers[0].head}, obfuscatedBlocks...)
	return infos
}

// newDispatchCondBlock returns a block that jumps to tblock if "phi op key" holds, or to fblock.
// tblock and fblock may be nil, to be filled in later.
// Preds of real target blocks are left untouched: their phis are assigned in their original predecessors.
func newDispatchCondBlock(ssaFunc *ssa.Function, phi *ssa.Phi, op token.Token, key int, tblock, fblock *ssa.BasicBlock) *ssa.BasicBlock {
	cond := &ssa.BinOp{X: phi, Op: op, Y: makeSsaInt(key)}
	setType(cond, types.Typ[types.Bool])
	*phi.Referrers() = append(*phi.Referrers(), cond)

	ifInstr := &ssa.If{Cond: cond}
	*cond.Referrers() = append(*cond.Referrers(), ifInstr)

	block := &ssa.BasicBlock{
		Comment: "ctrflow.dispatch",
		Instrs:  []ssa.Instruction{cond, ifInstr},
		Succs:   []*ssa.BasicBlock{tblock, fblock},
	}
	setBlockParent(block, ssaFunc)
	setBlock(cond, block)
	setBlock(ifInstr, block)
	return block
}

// bogusTarget returns a random target other than the one at index skip, when possible.
// It is used for branches of the dispatcher that are never taken.
func bogusTarget(entries []dispatchEntry, skip int, obfRand *mathrand.Rand) *ssa.BasicBlock {
	if len(entries) == 1 {
		return entries[0].target
	}
	idx := obfRand.Intn(len(entries) - 1)
	if idx >= skip {
		idx++
	}
	return entries[idx].target
}

// buildChainDispatch builds a chain of equality checks in random order.
// The final false branch is never taken, so it leads to a random target.
func buildChainDispatch(ssaFunc *ssa.Function, phi *ssa.Phi, entries []dispatchEntry, obfRand *mathrand.Rand) (*ssa.BasicBlock, []*ssa.BasicBlock) {
	order := obfRand.Perm(len(entries))
	blocks := make([]*ssa.BasicBlock, len(order))
	for i, idx := range order {
		e := entries[idx]
		blocks[i] = newDispatchCondBlock(ssaFunc, phi, token.EQL, e.key, e.target, nil)
		if i > 0 {
			blocks[i-1].Succs[1] = blocks[i]
			blocks[i].Preds = append(blocks[i].Preds, blocks[i-1])
		}
	}
	blocks[len(blocks)-1].Succs[1] = bogusTarget(entries, order[len(order)-1], obfRand)
	return blocks[0], blocks
}

// buildTreeDispatch builds a binary search tree over the state values with
// random split points, pivots and comparison operators.
// A leaf either jumps straight to its target, or checks the state value
// and leads to a random target on the branch that is never taken.
func buildTreeDispatch(ssaFunc *ssa.Function, phi *ssa.Phi, entries []dispatchEntry, obfRand *mathrand.Rand) (*ssa.BasicBlock, []*ssa.BasicBlock) {
	sorted := slices.Clone(entries)
	slices.SortFunc(sorted, func(a, b dispatchEntry) int { return cmp.Compare(a.key, b.key) })

	var blocks []*ssa.BasicBlock
	link := func(from *ssa.BasicBlock, to *ssa.BasicBlock) {
		if slices.Contains(blocks, to) {
			to.Preds = append(to.Preds, from)
		}
	}

	var build func(lo, hi int) *ssa.BasicBlock
	build = func(lo, hi int) *ssa.BasicBlock {
		if hi-lo == 1 {
			e := sorted[lo]
			// Checking the leaf is only possible below a condition block, as the
			// tree root must be a block of its own.
			if lo != 0 || hi != len(sorted) {
				if obfRand.Intn(2) == 0 {
					return e.target
				}
			}
			block := newDispatchCondBlock(ssaFunc, phi, token.EQL, e.key, e.target, bogusTarget(sorted, lo, obfRand))
			if obfRand.Intn(2) == 0 {
				block.Instrs[0].(*ssa.BinOp).Op = token.NEQ
				block.Succs[0], block.Succs[1] = block.Succs[1], block.Succs[0]
			}
			blocks = append(blocks, block)
			return block
		}

		// Split point biased towards the middle.
		n := hi - lo
		mid := lo + 1 + (obfRand.Intn(n-1)+obfRand.Intn(n-1)+1)/2
		lowMax, highMin := sorted[mid-1].key, sorted[mid].key

		left, right := build(lo, mid), build(mid, hi)

		var block *ssa.BasicBlock

		// Pick a pivot so that "state < pivot" (or the equivalent form) separates both halves.
		switch obfRand.Intn(4) {
		case 0: // state < pivot, pivot in (lowMax, highMin]
			block = newDispatchCondBlock(ssaFunc, phi, token.LSS, lowMax+1+obfRand.Intn(highMin-lowMax), left, right)
		case 1: // state <= pivot, pivot in [lowMax, highMin)
			block = newDispatchCondBlock(ssaFunc, phi, token.LEQ, lowMax+obfRand.Intn(highMin-lowMax), left, right)
		case 2: // state > pivot, pivot in [lowMax, highMin)
			block = newDispatchCondBlock(ssaFunc, phi, token.GTR, lowMax+obfRand.Intn(highMin-lowMax), right, left)
		case 3: // state >= pivot, pivot in (lowMax, highMin]
			block = newDispatchCondBlock(ssaFunc, phi, token.GEQ, lowMax+1+obfRand.Intn(highMin-lowMax), right, left)
		}
		blocks = append(blocks, block)
		link(block, left)
		link(block, right)
		return block
	}
	return build(0, len(sorted)), blocks
}

// addJunkBlocks adds junk jumps into random blocks. Can create chains of junk jumps.
func addJunkBlocks(ssaFunc *ssa.Function, count int, obfRand *mathrand.Rand) {
	if count == 0 {
		return
	}
	var candidates []*ssa.BasicBlock
	for _, block := range ssaFunc.Blocks {
		if len(block.Succs) > 0 {
			candidates = append(candidates, block)
		}
	}

	if len(candidates) == 0 {
		return
	}

	for i := range count {
		targetBlock := candidates[obfRand.Intn(len(candidates))]
		succsIdx := obfRand.Intn(len(targetBlock.Succs))
		succs := targetBlock.Succs[succsIdx]

		fakeBlock := &ssa.BasicBlock{
			Comment: "ctrflow.fake." + strconv.Itoa(i),
			Instrs:  []ssa.Instruction{&ssa.Jump{}},
			Preds:   []*ssa.BasicBlock{targetBlock},
			Succs:   []*ssa.BasicBlock{succs},
		}
		setBlockParent(fakeBlock, ssaFunc)
		targetBlock.Succs[succsIdx] = fakeBlock
		replacePred(succs, targetBlock, fakeBlock)

		ssaFunc.Blocks = append(ssaFunc.Blocks, fakeBlock)
		candidates = append(candidates, fakeBlock)
	}
}

// applySplitting splits biggest block into 2 parts of random size.
// Returns false if no block large enough for splitting is found
func applySplitting(ssaFunc *ssa.Function, obfRand *mathrand.Rand) bool {
	var targetBlock *ssa.BasicBlock
	for _, block := range ssaFunc.Blocks {
		if targetBlock == nil || len(block.Instrs) > len(targetBlock.Instrs) {
			targetBlock = block
		}
	}

	const minInstrCount = 1 + 1 // 1 exit instruction + 1 any instruction
	// Phis must stay in the block they start in: their edges are indexed by the
	// predecessor list of that block, so moving some of them into the new block
	// would leave edges for predecessors the new block does not have.
	phiCount := 0
	if targetBlock != nil {
		for _, instr := range targetBlock.Instrs {
			if _, ok := instr.(*ssa.Phi); !ok {
				break
			}
			phiCount++
		}
	}
	if targetBlock == nil || len(targetBlock.Instrs)-phiCount <= minInstrCount {
		return false
	}

	splitIdx := phiCount + 1 + obfRand.Intn(len(targetBlock.Instrs)-phiCount-2)

	firstPart := make([]ssa.Instruction, splitIdx+1)
	copy(firstPart, targetBlock.Instrs)
	firstPart[len(firstPart)-1] = &ssa.Jump{}

	secondPart := targetBlock.Instrs[splitIdx:]
	targetBlock.Instrs = firstPart

	newBlock := &ssa.BasicBlock{
		Comment: "ctrflow.split." + strconv.Itoa(targetBlock.Index),
		Instrs:  secondPart,
		Preds:   []*ssa.BasicBlock{targetBlock},
		Succs:   targetBlock.Succs,
	}
	setBlockParent(newBlock, ssaFunc)
	for _, instr := range newBlock.Instrs {
		setBlock(instr, newBlock)
	}

	// Fix preds for ssa.Phi working
	for _, succ := range targetBlock.Succs {
		for i, pred := range succ.Preds {
			if pred == targetBlock {
				succ.Preds[i] = newBlock
			}
		}
	}

	ssaFunc.Blocks = append(ssaFunc.Blocks, newBlock)
	targetBlock.Succs = []*ssa.BasicBlock{newBlock}
	return true
}

// addTrashBlockMarkers adds unreachable blocks with ssa2ast.MarkerInstr to further generate trash statements.
// Each trash block is guarded by an opaque predicate, stored into ssaRemap as the replacement of a placeholder condition.
func addTrashBlockMarkers(ssaFunc *ssa.Function, count int, opaque *opaquePredicates, ssaRemap map[ssa.Value]ast.Expr, obfRand *mathrand.Rand) {
	var candidates []*ssa.BasicBlock
	for _, block := range ssaFunc.Blocks {
		if len(block.Succs) > 0 {
			candidates = append(candidates, block)
		}
	}

	if len(candidates) == 0 {
		return
	}

	for range count {
		targetBlock := candidates[obfRand.Intn(len(candidates))]
		succsIdx := obfRand.Intn(len(targetBlock.Succs))
		succs := targetBlock.Succs[succsIdx]

		cond := ssa.NewConst(constant.MakeBool(false), types.Typ[types.Bool])
		trashOnTrue := obfRand.Intn(2) == 0
		ssaRemap[cond] = opaque.Predicate(!trashOnTrue)
		jmpInstr := &ssa.If{Cond: cond}

		trashBlock := &ssa.BasicBlock{
			Comment: "ctrflow.trash." + strconv.Itoa(targetBlock.Index),
			Instrs: []ssa.Instruction{
				ssa2ast.MarkerInstr,
				&ssa.Jump{},
			},
		}
		setBlockParent(trashBlock, ssaFunc)

		trashBlockDispatch := &ssa.BasicBlock{
			Comment: "ctrflow.trash.cond." + strconv.Itoa(targetBlock.Index),
			Instrs:  []ssa.Instruction{jmpInstr},
			Preds:   []*ssa.BasicBlock{targetBlock},
			Succs:   []*ssa.BasicBlock{trashBlock, succs},
		}
		if !trashOnTrue {
			trashBlockDispatch.Succs[0], trashBlockDispatch.Succs[1] = succs, trashBlock
		}
		setBlockParent(trashBlockDispatch, ssaFunc)
		targetBlock.Succs[succsIdx] = trashBlockDispatch

		replacePred(succs, targetBlock, trashBlockDispatch)

		trashBlock.Preds = []*ssa.BasicBlock{trashBlockDispatch, trashBlock}
		trashBlock.Succs = []*ssa.BasicBlock{trashBlock}

		ssaFunc.Blocks = append(ssaFunc.Blocks, trashBlockDispatch, trashBlock)
	}
}

// replacePred records that block is now reached through newPred instead of
// oldPred. ssa2ast emits phi assignments at the end of each block in Preds, so a
// stale oldPred entry breaks once applySplitting moves the values used by the phi
// into a new block.
func replacePred(block, oldPred, newPred *ssa.BasicBlock) {
	for i, pred := range block.Preds {
		if pred == oldPred {
			block.Preds[i] = newPred
			return
		}
	}
}

func fixBlockIndexes(ssaFunc *ssa.Function) {
	for i, block := range ssaFunc.Blocks {
		block.Index = i
	}
}
