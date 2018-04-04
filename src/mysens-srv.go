package main

import(
	"fmt"
	"net"
	"os"
	"bufio"
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha1"
	"strconv"
	"math/big"
)

var listenAddr = &net.TCPAddr{IP: net.IPv4(192,168,1,234), Port: 0}

const(
	// Используемый tcp протокол
	tcpProtocol = "tcp4"
	
	// Длина генерируемого rsa ключа
	keySize = 1024
	
	// Максимальная длина шифруемого сообщения в байтах
	readWriterSize = keySize/8
)

type remoteConn struct {
	c *net.TCPConn
	pubK *rsa.PublicKey	
}

func checkErr(err error){ 
	if err != nil {
		// Выводим текст ошибки
		fmt.Println(err) 

		// Завершаем программу
		os.Exit(1) 
	}
}

func getRemoteConn(c *net.TCPConn) *remoteConn{
	return &remoteConn{c: c, pubK: waitPubKey(bufio.NewReader(c))}
}

// Вернёт ссылку на структуру данных rsa.PublicKey
func waitPubKey(buf *bufio.Reader) (*rsa.PublicKey) {
	
	// Читаем строку из буфера
	line, _, err := buf.ReadLine(); checkErr(err)
	
	// Так как тип line - []byte (срез байт)
	// то для удобства сравнения переконвертируем <code><b>line</b></code> в строку
	if string(line) == "CONNECT" {
		
		// Далее мы будем читать буфер в том же порядке, в котором отправляем данные с клиента
		line, _, err := buf.ReadLine(); checkErr(err) // Читаем PublicKey.N

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
		line, _, err = buf.ReadLine(); checkErr(err)

		// Используемый пакет strconv для конвертации тип string в тип int
		pubKey.E, err = strconv.Atoi(string(line)); checkErr(err)
		
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
	// Слушаем любой свободны порт
	l, err := net.ListenTCP(tcpProtocol, listenAddr); checkErr(err)
	
	// Выведем прослушиваемый порт
	fmt.Println("Listen port: ", l.Addr().(*net.TCPAddr).Port)
	// l == *net.TCPListener == ссылка на тип данных
	// .Addr() http://golang.org/pkg/net/#TCPListener.Addr == метод для *net.TCPListener который возвращает "интерфейс"
	// net.Addr http://golang.org/pkg/net/#Addr который в свою очередь содержит ссылку на TCPAddr - *net.TCPAddr 
	// и два метода Network() и String()

	c, err := l.AcceptTCP(); checkErr(err)
	// На этом этапе программа приостанавливает свою работу ожидая соединения по прослушиваемому порту
	// AcceptTCP() - метод для *net.TCPListener http://golang.org/pkg/net/#TCPListener.AcceptTCP 
	//Возвращает установленное соединение и ошибку
	
	fmt.Println("Connect from:", c.RemoteAddr())
	// Вот 3 варианта которые подставив в fmt.Print[f|ln]() получим одинаковый результат
	// 1. c.RemoteAddr()
	// 2. c.RemoteAddr().(*net.TCPAddr)
	// 3. c.RemoteAddr().String()
	// В первый двух случаях функции: fmt.Println(), fmt.Print(), fmt.Printf() попытаются найти метод String()
	// Иначе вывод будет таким как есть
	
	// Таким образом мы получим соединение и ключ которым можно зашифровать это соединение
	rConn := getRemoteConn(c)

	// Шифруем и отправляем сообщения
	rConn.sendCommand("Go Language Server v0.1 for learning")
	rConn.sendCommand("Привет!")
	rConn.sendCommand("Привіт!")
	rConn.sendCommand("Прывітанне!")
	rConn.sendCommand("Hello!")
	rConn.sendCommand("Salut!")
	rConn.sendCommand("ハイ!")
	rConn.sendCommand("您好!")
	rConn.sendCommand("안녕!")
	rConn.sendCommand("Hej!")
}

func main() {
	listen()
}