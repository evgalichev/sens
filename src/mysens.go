package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	"net"
	"os"
	"strconv"
)

const (
	keySize        = 1024
	readWriterSize = keySize / 8
)

func checkErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var connectAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50137}

func connectTo() *net.TCPConn {
	fmt.Println("Connect to", connectAddr)
	c, err := net.DialTCP("tcp4", nil, connectAddr)
	checkErr(err)
	return c
}

// Функция в определённом порядке отправляет PublicKey
func sendKey(c *net.TCPConn, k *rsa.PrivateKey) {
	c.Write([]byte("CONNECT\n"))

	// передаём N типа *big.Int
	c.Write([]byte(k.PublicKey.N.String() + "\n"))
	// String() конвертирует *big.Int в string

	// передаём E типа int
	c.Write([]byte(strconv.Itoa(k.PublicKey.E) + "\n"))
	// strconv.Itoa() конвертирует int в string

	// []byte() конвертирует "строку" в срез байт
}

// Читает и освобождает определённый кусок буфера
// Вернёт срез байт
func getBytes(buf *bufio.Reader, n int) []byte {
	// Читаем n байт
	bytes, err := buf.Peek(n)
	checkErr(err)
	// Освобождаем n байт
	skipBytes(buf, n)
	return bytes
}

// Освобождает, пропускает определённое количество байт
func skipBytes(buf *bufio.Reader, skipCount int) {
	for i := 0; i < skipCount; i++ {
		buf.ReadByte()
	}
}

func main() {
	c := connectTo()
	buf := bufio.NewReader(c)

	// Создаём приватный ключ в составе которого уже есть публичный ключ
	k, err := rsa.GenerateKey(rand.Reader, keySize)
	checkErr(err)

	// Отправляем серверу публичный ключ
	sendKey(c, k)

	for {
		// Получаем зашифрованное сообщение в байтах
		cryptMsg := getBytes(buf, readWriterSize)

		// Расшифровываем сообщение
		msg, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, k, cryptMsg, nil)

		// Проверяем на ошибку
		checkErr(err)

		// Выводим расшифрованное сообщение
		fmt.Println(string(msg))
	}
}