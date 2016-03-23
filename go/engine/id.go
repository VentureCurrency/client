// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package engine

import (
	"github.com/keybase/client/go/libkb"
	keybase1 "github.com/keybase/client/go/protocol"
)

type IDRes struct {
	Outcome           *libkb.IdentifyOutcome
	User              *libkb.User
	TrackToken        keybase1.TrackToken
	ComputedKeyFamily *libkb.ComputedKeyFamily
}

// IDEngine is the type used by cmd_id Run, daemon id handler.
type IDEngine struct {
	arg *keybase1.IdentifyArg
	res *IDRes
	libkb.Contextified
}

func NewIDEngine(arg *keybase1.IdentifyArg, g *libkb.GlobalContext) *IDEngine {
	return &IDEngine{
		arg:          arg,
		Contextified: libkb.NewContextified(g),
	}
}

func (e *IDEngine) Name() string {
	return "Id"
}

func (e *IDEngine) Prereqs() Prereqs {
	return Prereqs{}
}

func (e *IDEngine) RequiredUIs() []libkb.UIKind {
	return []libkb.UIKind{
		libkb.IdentifyUIKind,
		libkb.LogUIKind,
	}
}

func (e *IDEngine) SubConsumers() []libkb.UIConsumer {
	return []libkb.UIConsumer{
		&Identify{},
	}
}

func (e *IDEngine) Run(ctx *Context) (err error) {
	e.res, err = e.run(ctx)
	return err
}

func (e *IDEngine) Result() *IDRes {
	return e.res
}

func (e *IDEngine) run(ctx *Context) (*IDRes, error) {
	iarg := NewIdentifyArg(e.arg.UserAssertion, false, e.arg.ForceRemoteCheck)
	iarg.Source = e.arg.Source
	ieng := NewIdentify(iarg, e.G())
	if err := RunEngine(ieng, ctx); err != nil {
		return nil, err
	}

	user := ieng.User()
	res := &IDRes{Outcome: ieng.Outcome(), User: user, TrackToken: ieng.TrackToken(), ComputedKeyFamily: user.GetComputedKeyFamily()}
	res.Outcome.Reason = e.arg.Reason

	if ieng.DidShortCircuit() {
		return res, nil
	}

	// need to tell any ui clients the track token
	if err := ctx.IdentifyUI.ReportTrackToken(ieng.TrackToken()); err != nil {
		return nil, err
	}

	ctx.IdentifyUI.Finish()
	return res, nil
}

func (ir *IDRes) Export() *keybase1.IdentifyRes {
	return &keybase1.IdentifyRes{
		Outcome:    *((*ir.Outcome).Export()),
		User:       ir.User.Export(),
		TrackToken: ir.TrackToken,
		PublicKeys: ir.ComputedKeyFamily.Export(),
	}
}
