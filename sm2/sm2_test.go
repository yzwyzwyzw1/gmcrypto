package sm2

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"testing"

)


func TestGetSm2P256V1(t *testing.T) {
	curve := P256Sm2()
	fmt.Printf("P:%s\n", curve.Params().P.Text(16))
	fmt.Printf("B:%s\n", curve.Params().B.Text(16))
	fmt.Printf("N:%s\n", curve.Params().N.Text(16))
	fmt.Printf("Gx:%s\n", curve.Params().Gx.Text(16))
	fmt.Printf("Gy:%s\n", curve.Params().Gy.Text(16))
}


func TestGenerateKey(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Printf("priv:%s\n", priv.D.Text(16))
	fmt.Printf("x:%s\n", priv.PublicKey.X.Text(16))
	fmt.Printf("y:%s\n", priv.PublicKey.Y.Text(16))

	curve := P256Sm2()
	if !curve.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Error("x,y is not on Curve")
		return
	}
	fmt.Println("x,y is on sm2 Curve")
}

func TestEncryptDecrypt(t *testing.T) {
	src := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}

	cipherText, err := Encrypt(&priv.PublicKey, src)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Printf("cipher text:%s\n", hex.EncodeToString(cipherText))

	plainText, err := Decrypt(priv, cipherText)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Printf("plain text:%s\n", hex.EncodeToString(plainText))

	if !bytes.Equal(plainText, src) {
		t.Error("decrypt result not equal expected")
		return
	}
}


func TestSignerSignandVerify(t *testing.T) {
    in:="30450220213C6CD6EBD6A4D5C2D0AB38E29D441836D1457A8118D34864C247D727831962022100D9248480342AC8513CCDF0F89A2250DC8F6EB4F2471E144E9A812E0AF497F801"
	inBytes, _ := hex.DecodeString(in)
    priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}

    //Sign
	sign,err :=priv.Sign(rand.Reader , inBytes,nil)
	fmt.Println(sign)

	//verify sign
	pub := &priv.PublicKey
	if !pub.Verify(inBytes,sign) {
		t.Error("verify sign filed!")
	}
	fmt.Println("s")

}




func TestGenerateKeyEqul(t *testing.T) {
	t.Parallel()
	PrivateKey, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}

	PublicKey := new(PublicKey)
	PublicKey.Curve = P256Sm2()
	PublicKey.X = PrivateKey.X
	PublicKey.Y = PrivateKey.Y
	fmt.Println("(pub1)",PrivateKey.PublicKey)
	fmt.Println("(pub2)",*PublicKey)


}

