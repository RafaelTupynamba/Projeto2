package userlib

import (
    "fmt"
    "strings"
    "time"
    "errors"
    "log"

    "io"

    "crypto"
    "crypto/rsa"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha512"
    "crypto/aes"
    "crypto/cipher"

    "golang.org/x/crypto/argon2"
    "github.com/google/uuid"
)

type UUID = uuid.UUID

// Tamanho da chave RSA
var RSAKeySize = 2048

// Tamanho do bloco e da chave AES
var AESBlockSize = aes.BlockSize
var AESKeySize = 16

// Tamanho do hash e do MAC
var HashSize = sha512.Size


// Imprimição de depuração (true/false)
var DebugPrint = false

// DebugMsg. Função auxiliar: faz impressão formatada no stderr se
// o global DebugPrint estiver definido. Todos os nossos testes
// ignoram o stderr, então sinta-se à vontade para usá-la
// para qualquer tipo de teste que desejar.

func SetDebugStatus(status bool){
        DebugPrint = status
}

func DebugMsg(format string, args ...interface{}) {
    if DebugPrint {
        msg := fmt.Sprintf("%v ", time.Now().Format("15:04:05.00000"))
        log.Printf(msg+strings.Trim(format, "\r\n ")+"\n", args...)
    }
}

// RandomBytes. Função auxiliar: retorna uma fatia de bytes do tamanho
// especificado preenchida com dados aleatórios
func RandomBytes(bytes int) (data []byte) {
    data = make([]byte, bytes)
    if _, err := io.ReadFull(rand.Reader, data); err != nil {
        panic(err)
    }
    return
}

type PublicKeyType struct {
    KeyType string
    PubKey rsa.PublicKey
}

type PrivateKeyType struct {
    KeyType string
    PrivKey rsa.PrivateKey
}

// Variáveis de datastore e keystore
var datastore map[UUID][]byte = make(map[UUID][]byte)
var keystore map[string]PublicKeyType = make(map[string]PublicKeyType)


/*
********************************************
**         Funções do Datastore           **
**   DatastoreSet, DatastoreGet,          **
** DatastoreDelete, DatastoreClear        **
********************************************
*/

// Define o valor no datastore
func DatastoreSet(key UUID, value []byte) {
    foo := make([]byte, len(value))
    copy(foo, value)

    datastore[key] = foo
}

// Retorna o valor, se existir
func DatastoreGet(key UUID) (value []byte, ok bool) {
    value, ok = datastore[key]
    if ok && value != nil {
        foo := make([]byte, len(value))
        copy(foo, value)
        return foo, ok
    }
    return
}

// Remove uma chave
func DatastoreDelete(key UUID) {
    delete(datastore, key)
}

// Use esta função nos testes para redefinir o datastore como vazio
func DatastoreClear() {
    datastore = make(map[UUID][]byte)
}

// Use esta função nos testes para redefinir o keystore como vazio
func KeystoreClear() {
    keystore = make(map[string]PublicKeyType)
}

// Define o valor no keystore
func KeystoreSet(key string, value PublicKeyType) error {
    _, present := keystore[key]
    if present != false {
       return errors.New("Essa entrada no Keystore já foi ocupada.")
    }

    keystore[key] = value
    return nil
}

// Retorna o valor, se existir
func KeystoreGet(key string) (value PublicKeyType, ok bool) {
    value, ok = keystore[key]
    return
}

// Use esta função nos testes para obter o mapa subjacente,
// caso queira manipular o datastore.
func DatastoreGetMap() map[UUID][]byte {
    return datastore
}

// Use esta função nos testes para obter o mapa subjacente,
// caso queira manipular o keystore.
func KeystoreGetMap() map[string]PublicKeyType {
    return keystore
}


/*
********************************************
**      Criptografia de Chave Pública     **
**     PKEKeyGen, PKEEnc, PKEDec          **
********************************************
*/

// Quatro structs para ajudar a gerenciar suas diferentes chaves.
// Você deve ter apenas 1 de cada struct.
// keyType deve ser um dos seguintes:
//     "PKE": criptografia
//     "DS": autenticação e integridade

type PKEEncKey = PublicKeyType
type PKEDecKey = PrivateKeyType

type DSSignKey = PrivateKeyType
type DSVerifyKey = PublicKeyType

// Gera um par de chaves para criptografia de chave pública via RSA
func PKEKeyGen() (PKEEncKey, PKEDecKey, error) {
    RSAPrivKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
    RSAPubKey := RSAPrivKey.PublicKey

    var PKEEncKeyRes PKEEncKey
    PKEEncKeyRes.KeyType = "PKE"
    PKEEncKeyRes.PubKey = RSAPubKey

    var PKEDecKeyRes PKEDecKey
    PKEDecKeyRes.KeyType = "PKE"
    PKEDecKeyRes.PrivKey = *RSAPrivKey

    return PKEEncKeyRes, PKEDecKeyRes, err
}

// Criptografa um fluxo de bytes via RSA-OAEP com sha512 como hash
func PKEEnc(ek PKEEncKey, plaintext []byte) ([]byte, error) {
    RSAPubKey := &ek.PubKey

    if ek.KeyType != "PKE" {
        return nil, errors.New("Usando uma chave não-PKE para PKE.")
    }

    ciphertext, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, RSAPubKey, plaintext, nil)

    return ciphertext, err
}

// Descriptografa um fluxo de bytes criptografado com RSA-OAEP/sha512
func PKEDec(dk PKEDecKey, ciphertext []byte) ([]byte, error) {
    RSAPrivKey := &dk.PrivKey

    if dk.KeyType != "PKE" {
        return nil, errors.New("Usando uma chave não-PKE para PKE.")
    }

    decryption, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, RSAPrivKey, ciphertext, nil)

    return decryption, err
}


/*
********************************************
**           Assinatura Digital           **
**       DSKeyGen, DSSign, DSVerify       **
********************************************
*/

// Gera um par de chaves para assinatura digital via RSA
func DSKeyGen() (DSSignKey, DSVerifyKey, error) {
    RSAPrivKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
    RSAPubKey := RSAPrivKey.PublicKey

    var DSSignKeyRes DSSignKey
    DSSignKeyRes.KeyType = "DS"
    DSSignKeyRes.PrivKey = *RSAPrivKey

    var DSVerifyKeyRes DSVerifyKey
    DSVerifyKeyRes.KeyType = "DS"
    DSVerifyKeyRes.PubKey = RSAPubKey

    return DSSignKeyRes, DSVerifyKeyRes, err
}

// Assina um fluxo de bytes via SHA256 e PKCS1v15
func DSSign(sk DSSignKey, msg []byte) ([]byte, error) {
    RSAPrivKey := &sk.PrivKey

    if sk.KeyType != "DS" {
        return nil, errors.New("Usando uma chave não-DS para DS.")
    }

    hashed := sha512.Sum512(msg)

    sig, err := rsa.SignPKCS1v15(rand.Reader, RSAPrivKey, crypto.SHA512, hashed[:])

    return sig, err
}

// Verifica uma assinatura criada com SHA256 e PKCS1v15
func DSVerify(vk DSVerifyKey, msg []byte, sig []byte) error {
    RSAPubKey := &vk.PubKey

    if vk.KeyType != "DS" {
        return errors.New("Usando uma chave não-DS para DS.")
    }

    hashed := sha512.Sum512(msg)

    err := rsa.VerifyPKCS1v15(RSAPubKey, crypto.SHA512, hashed[:], sig)

    return err
}


/*
********************************************
**                HMAC                    **
**         HMACEval, HMACEqual            **
********************************************
*/

// Avalia o HMAC usando sha512
func HMACEval(key []byte, msg []byte) ([]byte, error) {
    if len(key) != 16 && len(key) != 24 && len(key) != 32 {
       panic(errors.New("A chave de entrada para HMAC deve ter 16, 24 ou 32 bytes."))
    }

    mac := hmac.New(sha512.New, key)
    mac.Write(msg)
    res := mac.Sum(nil)

    return res, nil
}

// Comparação de igualdade para hashes/MACs.
// NÃO vaza informações de tempo de execução.
func HMACEqual(a []byte, b []byte) bool {
    return hmac.Equal(a, b)
}


/*
********************************************
**               KDF                      **
**            Argon2Key                   **
********************************************
*/

// Argon2: Escolhe automaticamente uma combinação adequada de iterações e memória.
// Use esta função para gerar uma chave a partir de uma senha.
func Argon2Key(password []byte, salt []byte, keyLen uint32) []byte {
    return argon2.IDKey(password, salt, 1, 64*1024, 4, keyLen)
}


/*
********************************************
**        Criptografia Simétrica           **
**          SymEnc, SymDec                **
********************************************
*/

// Criptografa uma fatia de bytes com AES-CTR.
// O comprimento do iv deve ser == AESBlockSize
func SymEnc(key []byte, iv []byte, plaintext []byte) []byte {
    if len(iv) != AESBlockSize {
        panic("Comprimento do IV diferente de AESBlockSize")
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }

    mode := cipher.NewCBCEncrypter(block, iv)
    ciphertext := make([]byte, AESBlockSize + len(plaintext))
    copy(ciphertext[:AESBlockSize], iv)

    mode.CryptBlocks(ciphertext[AESBlockSize:], plaintext)

    return ciphertext
}

// Descriptografa um texto cifrado criptografado com AES-CBC
func SymDec(key []byte, ciphertext []byte) []byte {
    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }

    iv := ciphertext[:AESBlockSize]
    plaintext := make([]byte, len(ciphertext) - AESBlockSize)
    mode := cipher.NewCBCDecrypter(block, iv)

    mode.CryptBlocks(plaintext, ciphertext[AESBlockSize:])

    return plaintext
}
