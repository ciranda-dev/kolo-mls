package braid

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	kolobraid "github.com/ciranda-dev/kolo-braid"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"

	kolomls "github.com/ciranda-dev/kolo-mls"
	"github.com/ciranda-dev/kolo-mls/backendstore"
	"github.com/ciranda-dev/kolo-mls/cred"
	"github.com/ciranda-dev/kolo-mls/internal/kolotest"
	"github.com/ciranda-dev/kolo-mls/settle"
)

// childEnv names the environment variable that makes the test binary run as
// an admin device process.
const childEnv = "KOLO_MLS_ADMIN_PROCESS"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) != "" {
		if err := runChild(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "admin process:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// httpPins serves Pins over HTTP on 127.0.0.1 and is its client.
type httpPins struct{ base string }

func servePins(t *testing.T, p *memPins) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("k")
		switch r.Method {
		case http.MethodPut:
			b, err := io.ReadAll(r.Body)
			if err == nil {
				err = p.Put(r.Context(), key, b)
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		case http.MethodDelete:
			p.Delete(r.Context(), key)
		case http.MethodGet:
			if r.URL.Query().Get("list") != "" {
				max, _ := strconv.Atoi(r.URL.Query().Get("max"))
				keys, _ := p.List(r.Context(), key, r.URL.Query().Get("after"), max)
				io.WriteString(w, strings.Join(keys, "\n"))
				return
			}
			v, err := p.Get(r.Context(), key, 0)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Write(v)
		}
	}), ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return "http://" + l.Addr().String()
}

func (p *httpPins) do(ctx context.Context, method, query string, body []byte) ([]byte, int, error) {
	return p.doMax(ctx, method, query, body, 0)
}

// doMax is do that reads at most max bytes of the answer, any when max is
// 0 or less.
func (p *httpPins) doMax(ctx context.Context, method, query string, body []byte, max int) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, p.base+"/?"+query, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var r io.Reader = resp.Body
	if max > 0 {
		r = io.LimitReader(resp.Body, int64(max)+1)
	}
	b, err := io.ReadAll(r)
	if err == nil && max > 0 && len(b) > max {
		err = settle.ErrPinTooLarge
	}
	return b, resp.StatusCode, err
}

func (p *httpPins) Put(ctx context.Context, k string, v []byte) error {
	_, code, err := p.do(ctx, http.MethodPut, "k="+k, v)
	if err == nil && code != http.StatusOK {
		err = fmt.Errorf("pins: status %d", code)
	}
	return err
}

func (p *httpPins) Get(ctx context.Context, k string, max int) ([]byte, error) {
	b, code, err := p.doMax(ctx, http.MethodGet, "k="+k, nil, max)
	if err != nil {
		return nil, err
	}
	switch code {
	case http.StatusOK:
		return b, nil
	case http.StatusNotFound:
		return nil, settle.ErrMissing
	}
	return nil, fmt.Errorf("pins: status %d", code)
}

func (p *httpPins) List(ctx context.Context, prefix, after string, max int) ([]string, error) {
	b, code, err := p.do(ctx, http.MethodGet, "list=1&k="+prefix+"&after="+after+"&max="+strconv.Itoa(max), nil)
	if err == nil && code != http.StatusOK {
		err = fmt.Errorf("pins: status %d", code)
	}
	if err != nil || len(b) == 0 {
		return nil, err
	}
	return strings.Split(string(b), "\n"), nil
}

func (p *httpPins) Delete(ctx context.Context, k string) error {
	_, code, err := p.do(ctx, http.MethodDelete, "k="+k, nil)
	if err == nil && code != http.StatusOK {
		err = fmt.Errorf("pins: status %d", code)
	}
	return err
}

// child is an admin device process as the parent sees it.
type child struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Scanner
}

func (c *child) send(t *testing.T, words ...string) {
	t.Helper()
	if _, err := fmt.Fprintln(c.in, strings.Join(words, " ")); err != nil {
		t.Fatal(err)
	}
}

func (c *child) read(t *testing.T, want string) []string {
	t.Helper()
	if !c.out.Scan() {
		t.Fatalf("admin process ended: %v", c.out.Err())
	}
	f := strings.Fields(c.out.Text())
	if len(f) == 0 || f[0] != want {
		t.Fatalf("admin process said %q, want %s", c.out.Text(), want)
	}
	return f[1:]
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestMultiProcess runs a Kolo group with three admin devices in three processes, linked by
// their braid over kolo-secure and by pins over HTTP, both on 127.0.0.1, and member devices in
// the test process: 3, and 200 (40 under the race detector). Every device ends each epoch with
// the same epoch authenticator, and concurrent Commits of two processes settle as one.
func TestMultiProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	large := 200
	if raceEnabled {
		large = 40
	}
	for _, n := range []int{3, large} {
		t.Run(fmt.Sprintf("%d members", n), func(t *testing.T) { multiProcess(t, n) })
	}
}

func multiProcess(t *testing.T, members int) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	w := newWorld(t)
	w.ctx = ctx
	url := servePins(t, w.pins)
	env := newBraidEnv(t)
	founder := w.device("admin0", nil)
	w.create(founder, env.order(w, founder))
	fp := env.peer(founder)

	var kids []*child
	for range 2 {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(), childEnv+"=1", "KOLO_MLS_PINS="+url, "KOLO_MLS_BRAID="+fp.ls.Addr().String(), "KOLO_MLS_FOUNDER="+hex.EncodeToString(founder.dev.ID.PublicKey()))
		cmd.Stderr = os.Stderr
		in, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		c := &child{cmd: cmd, in: in, out: bufio.NewScanner(out)}
		c.out.Buffer(nil, 4<<20)
		kids = append(kids, c)
		t.Cleanup(func() {
			in.Close()
			cmd.Wait()
		})
		f := c.read(t, "request")
		welcome, err := fp.b.Admit(ctx, unhex(t, f[0]), unhex(t, f[1]), &kolobraid.AdmitOptions{GrowSettlers: true})
		if err != nil {
			t.Fatal(err)
		}
		c.send(t, "braid", hex.EncodeToString(welcome))
		c.read(t, "braid-ready")
	}

	// The two admin processes join the MLS group, with three member devices.
	var kps [][]byte
	var keys []ed25519.PublicKey
	for _, c := range kids {
		c.send(t, "keypackage")
		f := c.read(t, "keypackage")
		kps = append(kps, unhex(t, f[0]))
		keys = append(keys, unhex(t, f[1]))
	}
	var ms []*node
	for i := range members {
		m := w.device(fmt.Sprintf("member%d", i), nil)
		kps = append(kps, m.dev.KeyPackage(t, m.st))
		ms = append(ms, m)
	}
	epoch := founder.m.Epoch()
	welcome, err := founder.admin.Commit(ctx, kolomls.CommitOptions{Add: kps})
	if err != nil {
		t.Fatal(err)
	}
	w.pump(epoch+1, env.settle, 200)
	settled, err := w.pins.Get(ctx, settle.SettledKey(w.gid, epoch), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range kids {
		c.send(t, "mlsjoin", hex.EncodeToString(welcome), hex.EncodeToString(settled))
		c.read(t, "joined")
	}
	for _, m := range ms {
		cfg := w.config(m)
		mm, err := settle.JoinMember(m.st, welcome, settled, func(gid []byte, epoch uint64, max int) ([]byte, error) {
			return w.pins.Get(ctx, settle.TreeKey(gid, epoch), max)
		}, kolomls.JoinOptions{Config: cfg}, w.memberOptions(m))
		if err != nil {
			t.Fatal(err)
		}
		m.m = mm
		w.nodes = append(w.nodes, m)
	}

	// All three admins become settlers: q = 2 of 3, so every later Commit
	// needs a vote and a signature from another process.
	// The braid's seats grew to the three admins; roles name them once
	// they settle.
	wctx, wcancel := context.WithTimeout(ctx, time.Minute)
	env.waitFor(wctx, func() bool {
		st := fp.b.Status()
		return st.Seats == 3 && len(st.PendingConfig) == 0
	})
	// The view's roster is the one at its last applied entry.
	if _, err := fp.b.Append(wctx, []byte("seats")); err != nil {
		t.Fatal(err)
	}
	env.waitFor(wctx, func() bool {
		_, seats, _, err := fp.order.Roster()
		return err == nil && len(seats) == 3
	})
	wcancel()
	all := append([]ed25519.PublicKey{founder.dev.ID.PublicKey()}, keys...)
	roles, err := settle.NewRoles(fp.order.ID(), settle.Majority, all, all, w.limits)
	if err != nil {
		t.Fatal(err)
	}
	w.commit(founder, kolomls.CommitOptions{SetExtensions: true, Extensions: mustExts(t, roles)}, env.settle)
	agree := func() {
		t.Helper()
		want, _ := founder.m.EpochAuthenticator()
		e := founder.m.Epoch()
		for _, c := range kids {
			for round := 0; ; round++ {
				if round == 2000 {
					t.Fatalf("an admin process did not reach epoch %d", e)
				}
				c.send(t, "auth")
				f := c.read(t, "auth")
				if f[0] == strconv.FormatUint(e, 10) {
					if f[1] != hex.EncodeToString(want) {
						t.Fatalf("admin process at epoch %d has another epoch authenticator", e)
					}
					break
				}
				w.stepAdmins()
				env.settle()
			}
		}
	}
	agree()

	// Two epochs committed by this process, settled with the other processes.
	for i := range 2 {
		w.commit(founder, kolomls.CommitOptions{}, env.settle)
		w.send(ms[i], "epoch message")
		agree()
	}
	// Concurrent Commits: this process and an admin process commit at once.
	epoch = founder.m.Epoch()
	kids[0].send(t, "commit")
	if _, err := founder.admin.Commit(ctx, kolomls.CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	kids[0].read(t, "committed")
	w.pump(epoch+1, env.settle, 400)
	w.check()
	agree()
	// A removal decided across the processes; the removed device's stolen
	// state then reads nothing.
	victim := ms[2]
	thief := w.steal(victim)
	w.commit(founder, kolomls.CommitOptions{Remove: []uint32{victim.m.OwnLeaf()}}, env.settle)
	agree()
	for _, m := range ms[:2] {
		w.send(m, "after the removal")
	}
	if n := w.decryptsNothing(thief); n == 0 {
		t.Fatal("no later message tried")
	}
	for _, c := range kids {
		c.send(t, "quit")
		c.read(t, "bye")
	}
	t.Logf("3 admin processes, %d members: epoch %d, every device agrees", members, founder.m.Epoch())
}

// stepAdmins lets this process's admins step once, delivering what they
// apply.
func (w *world) stepAdmins() {
	for _, n := range w.admins() {
		if ap, err := n.admin.Step(w.ctx); err == nil && ap != nil {
			w.record(n, ap)
			w.gossip(n, ap)
		}
	}
}

// runChild is an admin device process: it joins the founder's braid, then
// the MLS group, and steps its Admin whenever its braid moves, answering
// the parent's commands on in and out.
func runChild(in io.Reader, out io.Writer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t := &childT{}
	pins := &httpPins{base: os.Getenv("KOLO_MLS_PINS")}
	founderKey, err := hex.DecodeString(os.Getenv("KOLO_MLS_FOUNDER"))
	if err != nil {
		return err
	}
	dev := kolotest.NewDevice(t, kolotest.Person(t), true)
	idx := NewIndex([]byte("mls/"), nil)
	apply := func(tx *kolobraid.Tx, e *kolobraid.Entry) error {
		_, err := idx.Apply(tx, e)
		return err
	}
	opts := kolobraid.Options{Backend: kolostore.NewMemory(), App: testApp, Apply: apply, Limits: braidLimits()}
	j, err := kolobraid.NewJoin(ctx, dev.ID, opts)
	if err != nil {
		return err
	}
	req, err := j.Request(nil)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "request", hex.EncodeToString(dev.ID.PublicKey()), hex.EncodeToString(req))
	sc := bufio.NewScanner(in)
	sc.Buffer(nil, 4<<20)
	next := func(want string) ([]string, error) {
		if !sc.Scan() {
			return nil, errors.New("parent closed")
		}
		f := strings.Fields(sc.Text())
		if len(f) == 0 || f[0] != want {
			return nil, fmt.Errorf("parent said %q, want %s", sc.Text(), want)
		}
		return f[1:], nil
	}
	f, err := next("braid")
	if err != nil {
		return err
	}
	welcome, _ := hex.DecodeString(f[0])
	b, err := j.Complete(ctx, welcome)
	if err != nil {
		return err
	}
	defer b.Close()
	conn, err := kolosecure.Dial(ctx, os.Getenv("KOLO_MLS_BRAID"), dev.ID, founderKey, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	go b.ServeConn(ctx, conn)
	moved := make(chan struct{}, 1)
	go func() {
		for {
			if _, err := b.Next(ctx); err != nil {
				return
			}
			select {
			case moved <- struct{}{}:
			default:
			}
		}
	}()
	fmt.Fprintln(out, "braid-ready")

	backend := kolostore.NewMemory()
	st := backendstore.New(backend, []byte("mls/"))
	auth := &cred.Authenticator{Now: time.Now}
	cfg := settle.NewConfig(auth, &settle.Policy{}, time.Now)
	if _, err := next("keypackage"); err != nil {
		return err
	}
	kp := dev.KeyPackage(t, st)
	fmt.Fprintln(out, "keypackage", hex.EncodeToString(kp), hex.EncodeToString(dev.ID.PublicKey()))
	f, err = next("mlsjoin")
	if err != nil {
		return err
	}
	mw, _ := hex.DecodeString(f[0])
	ms, _ := hex.DecodeString(f[1])
	m, err := settle.JoinMember(st, mw, ms, func(gid []byte, epoch uint64, max int) ([]byte, error) {
		return pins.Get(ctx, settle.TreeKey(gid, epoch), max)
	}, kolomls.JoinOptions{Config: cfg}, settle.MemberOptions{})
	if err != nil {
		return err
	}
	a, err := NewAdmin(dev.ID, NewBraidOrder(b, idx, nil), m, Options{Pins: pins, Now: time.Now, ApproveRoles: approveAll})
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "joined")

	var mu sync.Mutex
	stepErr := make(chan error, 1)
	var steps sync.WaitGroup
	// The stepping goroutine ends before the braid closes.
	defer steps.Wait()
	defer cancel()
	steps.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-moved:
			}
			mu.Lock()
			_, err := a.Step(ctx)
			mu.Unlock()
			if err != nil {
				stepErr <- err
				return
			}
		}
	})
	for sc.Scan() {
		select {
		case err := <-stepErr:
			return err
		default:
		}
		f := strings.Fields(sc.Text())
		mu.Lock()
		switch {
		case len(f) == 0:
		case f[0] == "auth":
			au, err := a.Member().EpochAuthenticator()
			if err != nil {
				mu.Unlock()
				return err
			}
			fmt.Fprintln(out, "auth", a.Member().Epoch(), hex.EncodeToString(au))
		case f[0] == "commit":
			if _, err := a.Commit(ctx, kolomls.CommitOptions{}); err != nil {
				mu.Unlock()
				return err
			}
			fmt.Fprintln(out, "committed")
		case f[0] == "quit":
			fmt.Fprintln(out, "bye")
			mu.Unlock()
			return nil
		}
		mu.Unlock()
	}
	return sc.Err()
}

// childT lets kolotest helpers run in a process with no testing.T: they
// call only Helper and Fatal, and a failure ends the process.
type childT struct {
	testing.TB
}

func (c *childT) Helper() {}

func (c *childT) Fatal(args ...any) {
	panic(fmt.Sprint(args...))
}
