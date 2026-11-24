package secrettree

// Next is PeekNext and Commit in one call, for the tests.
func (t *Tree) Next(l uint32, k Kind) (gen uint32, key, nonce []byte, err error) {
	lk, err := t.PeekNext(l, k)
	if err != nil {
		return 0, nil, nil, err
	}
	defer lk.Discard()
	if err := t.Commit(lk); err != nil {
		return 0, nil, nil, err
	}
	return lk.gen, lk.Key(), lk.Nonce(), nil
}

// Key is Peek and Commit in one call, for the tests.
func (t *Tree) Key(l uint32, k Kind, gen uint32) (key, nonce []byte, err error) {
	lk, err := t.Peek(l, k, gen)
	if err != nil {
		return nil, nil, err
	}
	defer lk.Discard()
	if err := t.Commit(lk); err != nil {
		return nil, nil, err
	}
	return lk.Key(), lk.Nonce(), nil
}
