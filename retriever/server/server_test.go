package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/retriever/libs/task"
	utils2 "github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"

	//"github.com/CESSProject/cess-go-sdk/utils"
	ecies "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestChannel(t *testing.T) {
	ch := make(chan string, 1)
	close(ch)
	data, ok := <-ch
	t.Log("result: ", ok, " data ", data)
}

// func TestGenCid(t *testing.T) {
// 	tfile := "../test_cd2n/buffer/a8a53a4a3f66203ffe3c41d50a70044ac728260ec1a955c8f71fbbbe912f363b/1b0997375a57ed9f6044c906c949669e13da8d5ecee54119bb246f64c1f56c2b"
// 	cli, err := client.NewIpfsClient("http://127.0.0.1:5001")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	cid, err := client.AddFileToIpfs(cli, context.Background(), tfile)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	t.Log(cid)

// 	data, err := client.GetDataInIpfs(cli, context.Background(), cid)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	t.Log(len(data))
// }

// func TestGetDataByCid(t *testing.T) {
// 	tfile := "./test.data"
// 	cli, err := client.NewIpfsClient("http://127.0.0.1:5001")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	cid := "QmcdoURWAqfjN7qEUjDGLCqTSFmbWwoJjWek4CzQMTseGD"
// 	err = client.GetFileInIpfs(cli, context.Background(), cid, tfile)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// }

// func TestSaveCid(t *testing.T) {
// 	cid := "QmXFBa92tEgNPRqiJjZrnw6SUJQGjcWyM5pwjpZX5fPQ85"
// 	did := "2298354023042304582304958203845028"
// 	cli, err := client.NewIpfsClient("http://127.0.0.1:5001")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	err = client.SaveDid2CidMap(cli, context.Background(), cid, did)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	t.Log("success")
// }

// func TestChangeAccount(t *testing.T) {
// 	bytes, err := utils.ParsingPublickey("cXi4TiTDwio5LAF63UAw5uBhviQqa1WCVvBtaq7kVq278YLZf")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	t.Log(bytes)
// }

func TestDealSubTask(t *testing.T) {
	var task task.ProvideTask
	for i := 0; i < 13; i++ {
		t.Log("sub task", task.AddSubTask())
		t.Log("bit map", task.BitMap)
	}
	t.Log("-----------------------------------")
	for i := 12; i >= 0; i-- {
		task.DelSubTask(i)
		t.Log("bit map", task.BitMap)
	}
}

func TestJson(t *testing.T) {

	jbytes, err := json.Marshal([]byte{1, 2, 3, 4, 5, 255})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(jbytes))
}

func TestVerifySign(t *testing.T) {
	hexKey := "cdce8911cc893c792cd93508322e7d3dda9c6625fb5aea8f157668680491502e"
	sk, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	address := crypto.PubkeyToAddress(sk.PublicKey)
	t.Log("address ", address)
	message := "hello world!! test aaa bbb ccc"
	hash := sha256.New()
	hash.Write([]byte(message))
	sign, err := crypto.Sign(hash.Sum(nil), sk)
	if err != nil {
		t.Fatal(err)
	}
	len := len(sign)
	t.Log("last element(v):", sign[len-1], len)
	t.Log("hex sign", hex.EncodeToString(sign))
	t.Log(crypto.CompressPubkey(&sk.PublicKey))
}

func TestSignVerify(t *testing.T) {
	hexKey := "cdce8911cc893c792cd93508322e7d3dda9c6625fb5aea8f157668680491502e"
	sk, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	message := "hello world!! test aaa bbb ccc"
	hash := sha256.New()
	hash.Write([]byte(message))
	data := hash.Sum(nil)
	sign, err := utils2.SignWithSecp256k1PrivateKey(sk, data)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(utils2.VerifySecp256k1Sign(crypto.CompressPubkey(&sk.PublicKey), data, sign))
}

func TestQueryTEEInfo(t *testing.T) {
	teeEndpoint := "http://139.180.142.180:1309"
	u, err := url.JoinPath(teeEndpoint, tsproto.QUERY_TEE_INFO)
	if err != nil {
		t.Fatal("join url path error", err)
	}
	data, err := tsproto.QueryTeeInfo(u)
	if err != nil {
		t.Fatal("query tee info error", err)
	}
	t.Log(data)
}

// func TestCreateCacheOrder(t *testing.T) {
// 	cli, err := chain.NewClient(
// 		chain.AccountPrivateKey("b22dbc78effaba221dcc12557def7aceca27bc3727f0d1a078b682bce2fe4ff8"),
// 		chain.ChainID(11330),
// 		chain.ConnectionRpcAddresss([]string{"wss://testnet-rpc.cess.cloud/ws/"}),
// 		chain.EthereumGas(1086940004600, 30000000),
// 	)
// 	if err != nil {
// 		t.Fatal(errors.Wrap(err, "register node error"))
// 	}

// 	contract, err := chain.NewProtoContract(
// 		cli.GetEthClient(),
// 		"0xD185AF24121d0D6a9A3e128fB27C3704569b5E91",
// 		"cdce8911cc893c792cd93508322e7d3dda9c6625fb5aea8f157668680491502e",
// 		cli.NewTransactionOption,
// 		cli.SubscribeFilterLogs,
// 	)
// 	if err != nil {
// 		t.Fatal(errors.Wrap(err, "register node error"))
// 	}

// 	// reward, err := contract.QueryNodeReward(common.HexToAddress("0x40907feE3e02465D39Ef05f7d714294D89F6d4f7"))
// 	// if err != nil {
// 	// 	t.Fatal(errors.Wrap(err, "register node error"))
// 	// }
// 	// t.Log("node reward:", reward)

// 	hash, err := contract.CreateCacheOrder(context.Background(), common.HexToAddress("0x47a778bAE665A1c63c53F1C2FeF39AE3551B4B9B"), "100000000000")
// 	if err != nil {
// 		t.Fatal(errors.Wrap(err, "create cache order error"))
// 	}
// 	t.Log("success, tx hash", hash)
// }

// func TestAudit(t *testing.T) {
// 	teeEndpoint := "http://139.180.142.180:1309"
// 	u, err := url.JoinPath(teeEndpoint, client.AUDIT_DATA_URL)
// 	if err != nil {
// 		t.Fatal("join url path error", err)
// 	}
// 	tfile := "../go.sum"
// 	cli, err := client.NewIpfsClient("http://127.0.0.1:5001")
// 	if err != nil {
// 		t.Fatal("new ipfs client error", err)
// 	}
// 	st := time.Now()
// 	t.Log("start add file to ipfs", st)
// 	cid, err := client.AddFileToIpfs(cli, context.Background(), tfile)
// 	if err != nil {
// 		t.Fatal("add file to ipfs error", err)
// 	}
// 	t.Log("add file to ipfs", time.Since(st))

// 	hexKey := "b22dbc78effaba221dcc12557def7aceca27bc3727f0d1a078b682bce2fe4ff8"
// 	sk, err := crypto.HexToECDSA(hexKey)
// 	if err != nil {
// 		t.Fatal("parse privite key error", err)
// 	}
// 	userAcc := crypto.PubkeyToAddress(sk.PublicKey)

// 	reqIdBytes, err := utils2.GetRandomBytes()
// 	if err != nil {
// 		t.Fatal("get random bytes error", err)
// 	}
// 	reqId := hex.EncodeToString(reqIdBytes)
// 	hash := sha256.New()
// 	hash.Write([]byte(reqId))

// 	sign, err := crypto.Sign(hash.Sum(nil), sk)
// 	if err != nil {
// 		t.Fatal("sign error", err)
// 	}

// 	nonce, err := utils2.GetRandomBytes()
// 	if err != nil {
// 		t.Fatal("gen nonce error", err)
// 	}

// 	pubkey := []byte{3, 156, 81, 231, 38, 235, 173, 109, 193, 216, 141, 22, 0, 240, 53, 231, 238, 31, 161, 196, 184, 105, 188, 199, 146, 255, 107, 215, 175, 36, 119, 106, 187}

// 	ecdhsk, err := ecies.GenerateKey()
// 	if err != nil {
// 		t.Fatal("gen ecdh private key error", err)
// 	}

// 	aeskey, ecdhpk, err := utils2.GetAESKeyEncryptedWithECDH(ecdhsk, pubkey)
// 	if err != nil {
// 		t.Fatal("gen aes key error", err)
// 	}
// 	nonce = nonce[:12]
// 	fpath, err := utils2.EncryptFile(tfile, aeskey, nonce)
// 	if err != nil {
// 		t.Fatal("encrypt file with aes error", err)
// 	}

// 	t.Log("cid", cid)
// 	t.Log("userAcc", userAcc.Hex()[2:])
// 	t.Log("requestId", reqId)
// 	t.Log("userSign", hex.EncodeToString(sign))
// 	t.Log("supplierAcc", "40907feE3e02465D39Ef05f7d714294D89F6d4f7")
// 	t.Log("nonce", hex.EncodeToString(nonce))
// 	t.Log("key", hex.EncodeToString(ecdhpk))
// 	t.Log("aesKey", hex.EncodeToString(aeskey))
// 	t.Log("encrypted file path", fpath)

// 	err = client.AuditData(u, fpath, "./audited_data", client.TeeReq{
// 		Cid:         cid,
// 		UserAcc:     userAcc.Hex()[2:],
// 		SupplierAcc: "40907feE3e02465D39Ef05f7d714294D89F6d4f7",
// 		RequestId:   reqId,
// 		UserSign:    sign,
// 		Key:         ecdhpk,
// 		Nonce:       nonce,
// 	})
// 	if err != nil {
// 		t.Fatal("audit data error", err)
// 	}
// }

func TestFetchCache(t *testing.T) {

	hexKey := "b22dbc78effaba221dcc12557def7aceca27bc3727f0d1a078b682bce2fe4ff8"
	sk, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		t.Fatal("parse privite key error", err)
	}
	userAcc := crypto.PubkeyToAddress(sk.PublicKey)

	reqIdBytes, err := utils2.GetRandomBytes()
	if err != nil {
		t.Fatal("get random bytes error", err)
	}
	reqId := hex.EncodeToString(reqIdBytes)
	hash := sha256.New()
	hash.Write([]byte(reqId))

	sign, err := crypto.Sign(hash.Sum(nil), sk)
	if err != nil {
		t.Fatal("sign error", err)
	}
	req := tsproto.CacheRequest{
		Did:       "09903a15d3a982fb4348c45c91e816f318cf376e0fa278821bd35f1afcd7180a",
		UserAddr:  userAcc.Hex()[2:],
		RequestId: reqId,
		ExtData:   "80b61c3b34678e3c305887f9762c2f1c9244e690649bebc40992ae0551977a6d",
		Exp:       int64(time.Second * 18),
		Sign:      sign,
	}
	jbytes, err := json.Marshal(req)
	if err != nil {
		t.Fatal("sign error", err)
	}
	t.Log("success ,req: ", string(jbytes))
}

func TestECDH(t *testing.T) {

	pubA, err := hex.DecodeString("03b4c44d6447670095a28701953a591f9960fd02d55108bfc4fa44a00ca7317985")
	if err != nil {
		t.Fatal(err)
	}

	pubB, err := hex.DecodeString("03d57e2a1c173305b3e1005dc8e2b5758b1db96c35fc7704f855875ddc8780cc88")
	if err != nil {
		t.Fatal(err)
	}

	skA, err := ecies.NewPrivateKeyFromHex("19045a1604328c07aeb2da07f3539709d43bfa575fd8f13e301461fc2b725354")
	if err != nil {
		t.Fatal(err)
	}
	skB, err := ecies.NewPrivateKeyFromHex("bde32b278cebc6b495108c844556bd1cfde03380691c31308beeaab990fd56fa")
	if err != nil {
		t.Fatal(err)
	}

	ecdhk1, _, _ := utils2.GetAESKeyEncryptedWithECDH(skA, pubB)
	t.Log(hex.EncodeToString(ecdhk1))
	ecdhk2, _, _ := utils2.GetAESKeyEncryptedWithECDH(skB, pubA)
	t.Log(hex.EncodeToString(ecdhk2))

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	ctxt, err := utils2.AesEncrypt([]byte("hello cd2n"), ecdhk1, nonce)
	if err != nil {
		t.Fatal(err)
	}
	log.Println("secrect:", hex.EncodeToString(ctxt))
	ptxt, err := utils2.AesDecrypt(ctxt, ecdhk1, nonce)
	if err != nil {
		t.Fatal(err)
	}
	log.Println("plantext:", string(ptxt))
}

func TestMarshalConfig(t *testing.T) {
	var conf config.Config
	ybytes, err := config.MarshalConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(ybytes))
}

func TestWalk(t *testing.T) {
	err := filepath.Walk("../test_cd2n/buffer", func(path string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		//c.AddWithData(info.Name(), path, info.Size())
		log.Println("filepath", path, "name", info.Name(), "size", info.Size())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("success")
}

func TestConnRedis(t *testing.T) {
	redisCli := client.NewRedisClient("127.0.0.1:6379", "retriever", "cess_network@6379")
	err := client.PublishMessage(redisCli, context.Background(), "test", "test data")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("success")
}
