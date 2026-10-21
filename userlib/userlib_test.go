package userlib

import "testing"
import "bytes"
import "encoding/hex"
import "github.com/google/uuid"

// O Golang possui uma rotina muito poderosa para construir testes.

// Execute com "go test" para rodar os testes.

// E "go test -v" para rodar em modo detalhado, para ver todo o log e
// quais testes passam/falham individualmente.

// E "go test -cover" para verificar a cobertura de código nos seus testes.

// Strings padrão para testes
var key1 []byte = []byte("cs161teststring1")
var key2 []byte = []byte("cs161teststring2")
var key3 []byte = []byte("cs161teststring3")
var key4 []byte = []byte("cs161teststring4")
var key5 []byte = []byte("cs161teststring5")

// Cria um UUID a partir dos bytes fornecidos.
// Use apenas para testes!
func UUIDFromBytes(t *testing.T, b []byte) (u UUID) {
    u, err := uuid.FromBytes(b)
    if err != nil {
        t.Error("Erro em FromBytes:", err)
    }

    return
}

func TestUUIDFromBytesDeterministic(t *testing.T) {
    UUID1 := UUIDFromBytes(t, key1)
    t.Log(UUID1)

    UUID2 := UUIDFromBytes(t, key1)
    t.Log(UUID2)

    if UUID1 != UUID2 {
        t.Error("UUID1 != UUID2")
        t.Log("UUID1:", UUID1)
        t.Log("UUID2:", UUID2)
    }
}

func TestDatastore(t *testing.T) {
    UUID1 := UUIDFromBytes(t, key1)
    UUID2 := UUIDFromBytes(t, key2)
    UUID3 := UUIDFromBytes(t, key3)

    DatastoreSet(UUID1, []byte("foo"))

    _, valid := DatastoreGet(UUID3)
    if valid {
        t.Error("Datastore recuperou UUID3 quando não deveria")
    }

    data, valid := DatastoreGet(UUID1)
    if !valid || string(data) != "foo" {
        t.Error("Erro ao recuperar 'foo' do UUID1")
    }

    _, valid = DatastoreGet(UUID3)
    if valid {
        t.Error("Retornou algo quando não deveria, oops")
    }

    DatastoreSet(UUID2, []byte("bar"))

    data, valid = DatastoreGet(UUID1)
    if !valid || string(data) != "foo" {
        t.Error("Erro ao recuperar 'foo' do UUID1")
    }

    DatastoreDelete(UUID1)

    _, valid = DatastoreGet(UUID1)
    if valid {
        t.Error("DatastoreGet teve sucesso mesmo após excluir UUID1")
    }

    data, valid = DatastoreGet(UUID2)
    if !valid || string(data) != "bar" {
        t.Error("Erro ao recuperar 'bar' do UUID2")
    }

    DatastoreClear()

    _, valid = DatastoreGet(UUID2)
    if valid {
        t.Error("DatastoreGet teve sucesso mesmo após DatastoreClear")
    }

    t.Log("Recuperação do Datastore", data)
    t.Log("Mapa do Datastore", DatastoreGetMap())
    DatastoreClear()
    t.Log("Mapa do Datastore", DatastoreGetMap())
}

func TestKeystore(t *testing.T) {
    RSAPubKey, _, err1 := PKEKeyGen()
    _, DSVerifyKey, err2 := DSKeyGen()

    if err1 != nil || err2 != nil {
        t.Error("PKEKeyGen() falhou")
    }

    KeystoreSet("user1", RSAPubKey)
    KeystoreSet("user2", DSVerifyKey)

    _, valid := KeystoreGet("user3")
    if valid {
        t.Error("Keystore recuperou UUID3 quando não deveria")
    }

    data, valid := KeystoreGet("user1")
    if !valid {
        t.Error("Chave armazenada em UUID1 não corresponde")
    }

    data, valid = KeystoreGet("user2")
    if !valid {
        t.Error("Chave armazenada em UUID2 não corresponde")
    }

    KeystoreClear()

    _, valid = KeystoreGet("user1")
    if valid {
        t.Error("KeystoreGet teve sucesso mesmo após KeystoreClear")
    }

    t.Log("Recuperação do Keystore", data)
    t.Log("Mapa do Keystore", KeystoreGetMap())
    KeystoreClear()
    t.Log("Mapa do Keystore", KeystoreGetMap())
}

func TestRSA(t *testing.T) {

    // Testa criptografia e descriptografia RSA
    RSAPubKey, RSAPrivKey, err := PKEKeyGen()
    if err != nil {
        t.Error("PKEKeyGen() falhou", err)
    }

    t.Log(RSAPubKey)
    ciphertext, err := PKEEnc(RSAPubKey, []byte("Squeamish Ossifrage"))
    if err != nil {
        t.Error("Erro em PKEEnc()", err)
    }

    decryption, err := PKEDec(RSAPrivKey, ciphertext)
    if err != nil || (string(decryption) != "Squeamish Ossifrage") {
        t.Error("Descriptografia falhou", err)
    }

    // Testa assinatura e verificação RSA
    DSSignKey, DSVerifyKey, err := DSKeyGen()
    if err != nil {
        t.Error("DSKeyGen() falhou", err)
    }

    sign, err := DSSign(DSSignKey, []byte("Squeamish Ossifrage"))
    if err != nil {
        t.Error("Falha na assinatura RSA")
    }

    err = DSVerify(DSVerifyKey, []byte("Squeamish Ossifrage"), sign)
    if err != nil {
        t.Error("Falha na verificação RSA")
    }

    err = DSVerify(DSVerifyKey, []byte("foo"), sign)
    if err == nil {
        t.Error("A verificação RSA funcionou quando não deveria")
    }

    t.Log("Retorno de erro", err)
}

func TestHMAC(t *testing.T) {
    msga := []byte("foo")
    msgb := []byte("bar")

    hmac1a, _ := HMACEval(key1, msga)
    hmac1b, _ := HMACEval(key1, msgb)
    if HMACEqual(hmac1a, hmac1b) {
        t.Error("HMACs são iguais para dados diferentes")
    }

    hmac2a, _ := HMACEval(key2, msga)
    if HMACEqual(hmac1a, hmac2a) {
        t.Error("HMACs são iguais para chaves diferentes")
    }

    hmac1a2, _ := HMACEval(key1, msga)
    if !HMACEqual(hmac1a, hmac1a2) {
        t.Error("HMACs não são iguais quando deveriam ser")
    }
}

func TestArgon2(t *testing.T) {
    val1 := Argon2Key([]byte("Password"), []byte("nosalt"), 32)
    val2 := Argon2Key([]byte("Password"), []byte("nosalt"), 64)
    val3 := Argon2Key([]byte("password"), []byte("nosalt"), 32)

    equal := bytes.Equal

    if equal(val1, val2) || equal(val1, val3) || equal(val2, val3) {
        t.Error("Problema com Argon2")
    }
    t.Log(hex.EncodeToString(val1))
    t.Log(hex.EncodeToString(val2))
    t.Log(hex.EncodeToString(val3))
}

func TestStreamCipher(t *testing.T) {
    iv := RandomBytes(16)
    t.Log("IV aleatório", iv)

    ciphertext := SymEnc(key1, iv, []byte("foo"))
    decryption := SymDec(key1, ciphertext)

    t.Log("Mensagem descriptografada:", string(decryption))
    if string(decryption) != "foo" {
        t.Error("Falha na descriptografia simétrica")
    }
}

// Exemplo de falha deliberada
// func TestFailure(t *testing.T){
//        t.Log("Este teste vai falhar")
//        t.Error("Teste de falha")
//}
