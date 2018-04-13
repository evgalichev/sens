package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"
)

var listenAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50137}

const (
	keySize        = 1024
	readWriterSize = keySize / 8
)

type remoteConn struct {
	c    *net.TCPConn
	pubK *rsa.PublicKey
}

func checkErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func getRemoteConn(c *net.TCPConn) *remoteConn {
	return &remoteConn{c: c, pubK: waitPubKey(bufio.NewReader(c))}
}

// Вернёт ссылку на структуру данных rsa.PublicKey
func waitPubKey(buf *bufio.Reader) *rsa.PublicKey {

	// Читаем строку из буфера
	line, _, err := buf.ReadLine()
	checkErr(err)

	// Так как тип line - []byte (срез байт)
	// то для удобства сравнения переконвертируем <code><b>line</b></code> в строку
	if string(line) == "CONNECT" {

		// Далее мы будем читать буфер в том же порядке, в котором отправляем данные с клиента
		line, _, err := buf.ReadLine()
		checkErr(err) // Читаем PublicKey.N

		// Создаём пустой rsa.PublicKey
		pubKey := rsa.PublicKey{N: big.NewInt(0)}
		// pubKey.N == 0
		// тип pubKey.N big.Int http://golang.org/pkg/big/#Int

		// Конвертируем полученную строку и запихиваем в pubKey.N big.Int
		pubKey.N.SetString(string(line), 10)
		// Метод SetString() получает 2 параметра:
		// string(line) - конвертирует полученные байты в строку
		// 10 - система исчисления используемая в данной строке
		// (2 двоичная, 8 восьмеричная, 10 десятичная, 16 шестнадцатеричная ...)

		// Читаем из буфера второе число для pubKey.E
		line, _, err = buf.ReadLine()
		checkErr(err)

		// Используемый пакет strconv для конвертации тип string в тип int
		pubKey.E, err = strconv.Atoi(string(line))
		checkErr(err)

		// возвращаем ссылку на rsa.PublicKey
		return &pubKey

	} else {

		// В этом случае дальнейшее действия программы не предусмотренною. По этому:
		// Выводим что получили
		fmt.Println("Error: unkown command ", string(line))
		os.Exit(1) // Завершаем программу
	}
	return nil
}

func (rConn *remoteConn) sendCommand(comm string) {

	// Зашифровываем сообщение
	eComm, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rConn.pubK, []byte(comm), nil)
	// sha1.New() вернёт данные типа hash.Hash
	// С таким же успехм можно использовать sha512.New() sha256.New() ...
	// rand.Reader тип которого io.Reader позволяет не задумываясь о платформе генерировать
	// случайные числа из /dev/unrandom будь то Linux или CryptGenRandom API будь то Windows
	// rConn.pubK - публичный ключ который мы получили в func waitPubKey
	// []byte(comm) - конвертируем строку comm в срез байт ([]byte)
	checkErr(err) // проверяем на ошибки

	// Передаём зашифрованное сообщение по заранее установленному соединению
	rConn.c.Write(eComm)
	// rConn.c какого типа? - net.TCPConn у которого есть метод Write()
	// http://golang.org/pkg/net/#TCPConn.Write
}

func listen() {
	l, err := net.ListenTCP("tcp4", listenAddr)
	checkErr(err)
	fmt.Println("Listen port: ", l.Addr().(*net.TCPAddr).Port)

	c, err := l.AcceptTCP()
	checkErr(err)

	fmt.Println("Connect from:", c.RemoteAddr())
	rConn := getRemoteConn(c)

	// Шифруем и отправляем сообщения
	rConn.sendCommand("Go Language Server v0.1 for learning")
	rConn.sendCommand("Привет!")
	time.Sleep(100 * time.Second)
}

func main() {
	listen()
}
