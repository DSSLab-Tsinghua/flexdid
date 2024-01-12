package psidentity

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	// "github.com/golang/protobuf/proto"
)

// type RsaKey struct {
// 	N big.Int //Z/nZ
// 	G big.Int // Generator
// }

// func (r *RsaKey) ProtoMessage() {}
// func (r *RsaKey) Reset() {
//     *r = RsaKey{}
// }
//  func (r *RsaKey) String() string {
//     // Implement the logic to generate a string representation of the struct
//     // and return it as a string
//     return "RsaKey string representation"
// }
/*
	Acc is the accumulator of the set (analogous to merkle root)
*/
// type Accumulator struct {
// 	Acc big.Int   // Accumulator
// 	U   []big.Int // set of members
// 	N   big.Int   //Z/nZ
// 	G   big.Int   // Generator

// }




// func (i *Psidentity) GenerateRevocationKey() ([]byte, error) {
func (i *Psidentity) NewRevocationKey() (*RsaKey, error) {
	return RsaKeygen(1024)
}

// Generate N and G
// lamda is the bit size of N(preferably 2048 bit)
// Note that the primes factors of N are not exposed for security reason
func RsaKeygen(lambda int) (*RsaKey, error) {

	privatekey, err := rsa.GenerateKey(rand.Reader, lambda)
	if err != nil {
		panic(err)
	}
	N := privatekey.PublicKey.N
	NBytes := N.Bytes()

	var F *big.Int

	//find gcd of F and N, i.e., find F co-prime with N
	for {
		F, err = rand.Int(rand.Reader, N)
		if new(big.Int).GCD(nil, nil, F, N).Cmp(big.NewInt(1)) == 0 && err == nil {
			break
		}
	}

	//func (z *Int) Exp(x, y, m *Int) *Int
	//z = x^y mod |m|
	G := new(big.Int).Exp(F, big.NewInt(2), privatekey.PublicKey.N)
	GBytes := G.Bytes()

	// rsaKey := &RsaKey{
	// 	N: NBytes,
	// 	G: GBytes,
	// }

	return &RsaKey{
		N: NBytes,
		G: GBytes,
	},nil

}














// // func (i *Psidentity) GenerateRevocationKey() ([]byte, error) {
// func (i *Psidentity) GenerateRevocationKey() ([]byte, error) {
// 	return RsaKeygen(1024)
// }

// // Generate N and G
// // lamda is the bit size of N(preferably 2048 bit)
// // Note that the primes factors of N are not exposed for security reason
// func RsaKeygen(lambda int) ([]byte, error) {

// 	privatekey, err := rsa.GenerateKey(rand.Reader, lambda)
// 	if err != nil {
// 		panic(err)
// 	}
// 	N := privatekey.PublicKey.N

// 	var F *big.Int

// 	//find gcd of F and N, i.e., find F co-prime with N
// 	for {
// 		F, err = rand.Int(rand.Reader, N)
// 		if new(big.Int).GCD(nil, nil, F, N).Cmp(big.NewInt(1)) == 0 && err == nil {
// 			break
// 		}
// 	}

// 	//func (z *Int) Exp(x, y, m *Int) *Int
// 	//z = x^y mod |m|
// 	G := new(big.Int).Exp(F, big.NewInt(2), privatekey.PublicKey.N)

// 	RK := &RsaKey{
// 		N: *N,
// 		G: *G,
// 	}

// 	SerializedRK, err := proto.Marshal(RK)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return SerializedRK, nil
// 	// rk, err := proto.Marshal(RsaKey)
// 	// return proto.Marshal(RsaKey)

// }

func CreateCRI(raw []byte) []byte {
	// var res *big.Int
	res := new(big.Int).SetBytes(raw)
	resp := Hprime(*res)
	return resp.Bytes()
}

// Generate the accumulator
func Generate_Acc(key RsaKey, U []big.Int) *Accumulator {

	Primes := make([]big.Int, len(U))
	GBytes := key.G
	var G *big.Int
	G = G.SetBytes(GBytes)


	UBytes := make([][]byte, len(U))
	for i, u := range U {
		Primes[i] = Hprime(u)
		UBytes[i] = u.Bytes()
		G.Exp(G, &Primes[i], new(big.Int).SetBytes(key.N))

	}

	return &Accumulator{
		Acc: G.Bytes(),
		U:   UBytes,
		N:   key.N,
		G:   key.G,
	}

}

// For storing Witnesses
// type WitnessList struct {
// 	Acc  big.Int
// 	List map[string]big.Int
// }

// Initializes a witness mapping
func (c *Accumulator) Witness_int() *WitnessList {

	list := make(map[string][]byte, len(c.U))
	return &WitnessList{Acc: c.Acc, List: list}

}

// update for new added element
// Generation of witness is multiplication of all primes mapped from members except the one we
// are proving,prod(say) then,
// Witness = G^prod(mod N)
func generate_witness(u big.Int, key RsaKey, U []big.Int) big.Int {

	N := key.N

	Primes := make([]big.Int, len(U))
	GBytes := key.G
	var G *big.Int
	G = G.SetBytes(GBytes)

	for i, u_dash := range U {
		Primes[i] = Hprime(u_dash)
		if u_dash.Cmp(&u) != 0 {
			G.Exp(G, &Primes[i], new(big.Int).SetBytes(N))
		}
	}
	return *G
}

// Whenever the set is passed or it changes there is a computation of new witnesses which takes O(nlogn)
// divide and conquer strategy
// update for existed elements
func (witness *WitnessList) Precompute_witness(G_prev big.Int, U []big.Int, accumulator *Accumulator) {

	GprevBytes := G_prev.Bytes()

	if len(U) == 1 {
		witness.List[U[0].String()] = GprevBytes
		witness.Acc = accumulator.Acc
		return
	}

	A := U[:len(U)/2]
	B := U[len(U)/2:]
	G1 := G_prev
	G2 := G_prev

	N := accumulator.N

	for _, u := range B {
		e1 := Hprime(u)

		G1.Exp(&G1, &e1, new(big.Int).SetBytes(N))
	}

	for _, w := range A {
		e2 := Hprime(w)
		G2.Exp(&G2, &e2, new(big.Int).SetBytes(N))
	}
	//fmt.Println(G1, G2)
	witness.Precompute_witness(G1, A, accumulator)
	witness.Precompute_witness(G2, B, accumulator)
}

/*
Adding new member to the set which autometically precomputes the all the Witnesses in O(n) time
*/
func (c *Accumulator) Add_member(u big.Int, w *WitnessList) {

	e := Hprime(u)

	AccBytes := c.Acc
	var Acc *big.Int
	Acc = Acc.SetBytes(AccBytes)

	preAcc := Acc

	newAcc := new(big.Int).Exp(Acc, &e, new(big.Int).SetBytes(c.N))
	newSet := append(c.U[:], u.Bytes())

	c.U = newSet

	c.Acc = newAcc.Bytes()

	newSetBigInt := make([]big.Int, len(newSet))
	for i, bytes := range newSet {
		var num big.Int
		num.SetBytes(bytes)
		newSetBigInt[i] = num
	}
	
	cUBigInt := newSetBigInt

	if len(w.List) == 0 {
		w.Precompute_witness(*new(big.Int).SetBytes(c.G), cUBigInt, c)
	} else {
		for _, x := range c.U {
			tempBytes := w.List[string(x)]
			var temp *big.Int
			temp = temp.SetBytes(tempBytes)
			resInt := *new(big.Int).Exp(temp, &e, new(big.Int).SetBytes(c.N))
			w.List[string(x)] = resInt.Bytes()
		}
		w.List[u.String()] = preAcc.Bytes()

	}

}

/*
Deleting a member from the set in O(nlogn) time
*/
func (c *Accumulator) Delete_member(u big.Int, w *WitnessList) {

	// var newSet []big.Int
	var newSet [][]byte
	var i int
	for i = 0; i < len(c.U); i++ {
		var cUi *big.Int
		cUi = cUi.SetBytes(c.U[i])
		if cUi.Cmp(&u) == 0 {
			newSet = append(c.U[:i], c.U[i+1:]...)
			break
		}
	}

	newAcc := w.List[u.String()]
	c.Acc = newAcc
	c.U = newSet
	list := make(map[string][]byte, len(c.U))
	w.List = list

	newSetBigInt := make([]big.Int, len(newSet))
	for i, bytes := range newSet {
		var num big.Int
		num.SetBytes(bytes)
		newSetBigInt[i] = num
	}
	
	cUBigInt := newSetBigInt

	w.Precompute_witness(*new(big.Int).SetBytes(c.G), cUBigInt, c)

}

/*
Verification is simply
W^e (mod N) == Acc
u and W are coming from the prover
Accumulator and N are stored on chain
Therefore, args[] should be constructed on chain
*/

func Verify(args []big.Int) bool {

	u, W, Accumulator, N := args[0], args[1], args[2], args[3]
	e := Hprime(u)
	Acc_dash := new(big.Int).Exp(&W, &e, &N)
	return Acc_dash.Cmp(&Accumulator) == 0

}
