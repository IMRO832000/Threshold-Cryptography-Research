package main

import (
	"errors"
	"fmt"
	"sync"
  "time"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
//	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"github.com/taurusgroup/multi-party-sig/protocols/example"
//	"github.com/taurusgroup/multi-party-sig/protocols/frost"
)

func XOR(id party.ID, ids party.IDSlice, n *test.Network) error {
	h, err := protocol.NewMultiHandler(example.StartXOR(id, ids), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(id, h, n)
	_, err = h.Result()
	if err != nil {
		return err
	}
	return nil
}

func CMPKeygen(id party.ID, ids party.IDSlice, threshold int, n *test.Network, pl *pool.Pool) (*cmp.Config, error) {
  //st8 := time.Now()
	h, err := protocol.NewMultiHandler(cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pl), nil)
	//fmt.Println(id,"key-gen-time",	time.Since(st8))

	if err != nil {
		return nil, err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func CMPRefresh(c *cmp.Config, n *test.Network, pl *pool.Pool) (*cmp.Config, error) {
	hRefresh, err := protocol.NewMultiHandler(cmp.Refresh(c, pl), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(c.ID, hRefresh, n)

	r, err := hRefresh.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func CMPSign(c *cmp.Config, m []byte, signers party.IDSlice, n *test.Network, pl *pool.Pool) error {

	h, err := protocol.NewMultiHandler(cmp.Sign(c, signers, m, pl), nil)

	if err != nil {
		return err
	}
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return err
	}
	signature := signResult.(*ecdsa.Signature)
	if !signature.Verify(c.PublicPoint(), m) {
		return errors.New("failed to verify cmp signature")
	}
	return nil
}

func CMPPreSign(c *cmp.Config, signers party.IDSlice, n *test.Network, pl *pool.Pool) (*ecdsa.PreSignature, error) {
	h, err := protocol.NewMultiHandler(cmp.Presign(c, signers, pl), nil)
	if err != nil {
		return nil, err
	}

	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return nil, err
	}

	preSignature := signResult.(*ecdsa.PreSignature)
	if err = preSignature.Validate(); err != nil {
		return nil, errors.New("failed to verify cmp presignature")
	}
	return preSignature, nil
}

func CMPPreSignOnline(c *cmp.Config, preSignature *ecdsa.PreSignature, m []byte, n *test.Network, pl *pool.Pool) error {
	h, err := protocol.NewMultiHandler(cmp.PresignOnline(c, preSignature, m, pl), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return err
	}
	signature := signResult.(*ecdsa.Signature)
	if !signature.Verify(c.PublicPoint(), m) {
		return errors.New("failed to verify cmp signature")
	}
	return nil
}




func All(id party.ID, ids party.IDSlice, threshold int, message []byte, n *test.Network, wg *sync.WaitGroup, pl *pool.Pool) error {
	defer wg.Done()

	// XOR
	err := XOR(id, ids, n)
	if err != nil {
		return err
	}

	// CMP KEYGEN
	fmt.Println("-----cmpkg-------")
	st1 := time.Now()
	keygenConfig, err := CMPKeygen(id, ids, threshold, n, pl)
	fmt.Println(time.Since(st1),id)

	if err != nil {
		return err
	}


	// CMP REFRESH
st2 :=time.Now()
	fmt.Println("------cmprefresh-------")
	refreshConfig, err := CMPRefresh(keygenConfig, n, pl)
	fmt.Println(time.Since(st2), id )
	if err != nil {
		return err
	}


	signers := ids[:threshold+1]
  fmt.Println("signers")
	fmt.Println(signers)
	if !signers.Contains(id) {
		n.Quit(id)
		return nil
	}

	// CMP SIGN
fmt.Println("CMP--sign---time")
st3 := time.Now()
	err = CMPSign(refreshConfig, message, signers, n, pl)
	fmt.Println(time.Since(st3),id)


	if err != nil {
		return err
	}


	// CMP PRESIGN
	fmt.Println("-----cmppresign&verificationtime--------")
	st4 := time.Now()
	preSignature, err := CMPPreSign(refreshConfig, signers, n, pl)
	fmt.Println(time.Since(st4),id)
  fmt.Println(preSignature)
	if err != nil {
		return err
	}

	// CMP PRESIGN ONLINE
	fmt.Println("----cmppso&verification---------")
	st5 :=time.Now()
	err = CMPPreSignOnline(refreshConfig, preSignature, message, n, pl)
	fmt.Println(time.Since(st5),id)

	if err != nil {
		return err
	}


	return nil

}





func main() {
	ids := party.IDSlice{"a1", "a2","a3","a4","a5","a6","a7","a8","a9","a10","a11","a12","a13","a14","a15"}
	threshold := 5
	messageToSign := []byte("Applied-Cryptography-project")

	net := test.NewNetwork(ids)
   fmt.Println(net)
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id party.ID) {
			pl := pool.NewPool(0)
			defer pl.TearDown()
			fmt.Println(id)

			if err := All(id, ids, threshold, messageToSign, net, &wg, pl);

			err != nil {
				fmt.Println(err)
			}
		}(id)
	}
	wg.Wait()

}
