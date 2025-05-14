package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
)

var (
	listenPort  string
	keyFilePath string
)

func init() {
	flag.StringVar(&listenPort, "l", "", "Specify listen port to run in server mode")
	flag.StringVar(&keyFilePath, "k", "", "Key file containing the passphrase")
}

func main() {
	flag.Parse()
	args := flag.Args()

	if keyFilePath == "" || (listenPort != "" && len(args) != 2) || (listenPort == "" && len(args) != 2) {
		fmt.Println("Incorrect usage:")
		if listenPort != "" {
			fmt.Println("\tServer: go run jumproxy.go -k mykey -l 8888 localhost 22")
		} else {
			fmt.Println("\tClient: ssh -o 'ProxyCommand go run jumproxy.go -k mykey localhost 8888' user@localhost")
		}
		os.Exit(1)
	}

	passphrase, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read passphrase: %v\n", err)
		os.Exit(1)
	}

	if listenPort != "" {
		initiateServer(listenPort, args[0], args[1], passphrase)
	} else {
		initiateClient(args[0], args[1], passphrase)
	}
}

func deriveKey(phrase, salt []byte) []byte {
	return pbkdf2.Key(phrase, salt, 4096, 32, sha256.New)
}

func secureData(data, key []byte) ([]byte, error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcmBlock, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmBlock.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	securedData := gcmBlock.Seal(nonce, nonce, data, nil)
	return securedData, nil
}

func decodeData(data, key []byte) ([]byte, error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcmBlock, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, err
	}
	nonceSize := gcmBlock.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("insufficient data for decryption")
	}
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	return gcmBlock.Open(nil, nonce, cipherText, nil)
}

func initiateServer(port, targetHost, targetPort string, passphrase []byte) {
	specialSalt := []byte("Setting this salt for assignment")
	masterKey := deriveKey(passphrase, specialSalt)

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to start server on port %s: %v", port, err)
	}
	defer listener.Close()

	logFile, _ := os.OpenFile("JumproxyLog.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	logger := log.New(logFile, "jumproxy-server: ", log.LstdFlags)
	defer logFile.Close()
	fmt.Println("Server is listening on port ", port)
	logger.Printf("Server is listening on port %s\n", port)
	for {
		connection, err := listener.Accept()
		if err != nil {
			fmt.Println("Failed to accept connection: %v\n", err)
			logger.Printf("Failed to accept connection: %v\n", err)
			continue
		}
		fmt.Println("Connection established with client: ", connection.RemoteAddr().String())
		logger.Printf("Connection established with client: ", connection.RemoteAddr().String())
		go manageConnection(connection, targetHost, targetPort, masterKey, logger)
	}
}

func manageConnection(conn net.Conn, destHost, destPort string, key []byte, logger *log.Logger) {
	defer conn.Close()
	destinationConn, err := net.Dial("tcp", net.JoinHostPort(destHost, destPort))
	if err != nil {
		fmt.Println("Failed to connect to the target service at \n", destHost, destPort, err)
		logger.Printf("Failed to connect to the target service at \n", destHost, destPort, err)
		return
	}
	defer destinationConn.Close()

	streamToTarget := make(chan bool)
	go func() {
		defer close(streamToTarget)
		bufferedReader := bufio.NewReader(conn)
		for {
			dataLengthBytes := make([]byte, 4)
			if _, err := io.ReadFull(bufferedReader, dataLengthBytes); err != nil {
				fmt.Println("Error reading data size: ", err)
				logger.Printf("Error reading data size: %v\n", err)
				return
			}
			dataSize := binary.BigEndian.Uint32(dataLengthBytes)
			encryptedData := make([]byte, dataSize)
			if _, err := io.ReadFull(bufferedReader, encryptedData); err != nil {
				fmt.Println("Error reading encrypted data: ", err)
				logger.Printf("Error reading encrypted data: %v\n", err)
				return
			}

			decryptedData, err := decodeData(encryptedData, key)
			if err != nil {
				fmt.Println("Decryption error: ", err)
				logger.Printf("Decryption error: %v\n", err)
				return
			}

			_, writeErr := destinationConn.Write(decryptedData)
			if writeErr != nil {
				fmt.Println("Error writing decrypted data to the target service: ", writeErr)
				logger.Printf("Error writing decrypted data to the target service: %v\n", writeErr)
				return
			}
		}
	}()

	bufferedWriter := bufio.NewWriter(conn)
	responseBuffer := make([]byte, 2048)
	for {
		select {
		case <-streamToTarget:
			return
		default:
			bytesRead, readErr := destinationConn.Read(responseBuffer)
			if readErr != nil {
				fmt.Println("Error reading response from the target service: ", readErr)
				logger.Printf("Error reading response from the target service: %v\n", readErr)
				return
			}

			encryptedResponse, encryptErr := secureData(responseBuffer[:bytesRead], key)
			if encryptErr != nil {
				fmt.Println("Error encrypting the target service response: ", encryptErr)
				logger.Printf("Error encrypting the target service response: %v\n", encryptErr)
				return
			}

			sizeBuffer := make([]byte, 4)
			binary.BigEndian.PutUint32(sizeBuffer, uint32(len(encryptedResponse)))
			if _, writeSizeErr := bufferedWriter.Write(sizeBuffer); writeSizeErr != nil {
				fmt.Println("Error writing encrypted response size: ", writeSizeErr)
				logger.Printf("Error writing encrypted response size: %v\n", writeSizeErr)
				return
			}

			if _, writeDataErr := bufferedWriter.Write(encryptedResponse); writeDataErr != nil {
				fmt.Println("Error writing encrypted response data: ", writeDataErr)
				logger.Printf("Error writing encrypted response data: %v\n", writeDataErr)
				return
			}
			bufferedWriter.Flush()
		}
	}
}

func initiateClient(serverAddr, serverPort string, passphrase []byte) {
	salt := []byte("Setting this salt for assignment")
	clientKey := deriveKey(passphrase, salt)

	clientConn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", serverAddr, serverPort))
	if err != nil {
		log.Fatalf("Error connecting to server at %s:%s: %v", serverAddr, serverPort, err)
	}
	defer clientConn.Close()

	clientLoggerFile, _ := os.OpenFile("JumproxyLog.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	clientLogger := log.New(clientLoggerFile, "jumproxy-client: ", log.LstdFlags)
	defer clientLoggerFile.Close()

	clientLogger.Printf("Successfully connected to the server at %s:%s", serverAddr, serverPort)

	signalHandlingChan := make(chan os.Signal, 1)
	signal.Notify(signalHandlingChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalHandlingChan
		clientLogger.Println("Received termination signal, exiting.")
		os.Exit(0)
	}()

	go func() {
		clientReader := bufio.NewReader(clientConn)
		for {
			lengthBuffer := make([]byte, 4)
			_, readLengthErr := io.ReadFull(clientReader, lengthBuffer)
			if readLengthErr != nil {
				if readLengthErr != io.EOF {
					clientLogger.Printf("Error reading length from server: %v", readLengthErr)
				}
				return
			}
			messageLength := binary.BigEndian.Uint32(lengthBuffer)

			encryptedMessage := make([]byte, messageLength)
			_, readMessageErr := io.ReadFull(clientReader, encryptedMessage)
			if readMessageErr != nil {
				clientLogger.Printf("Error reading encrypted message from server: %v", readMessageErr)
				return
			}

			decryptedMessage, decryptionErr := decodeData(encryptedMessage, clientKey)
			if decryptionErr != nil {
				clientLogger.Printf("Decryption error: %v", decryptionErr)
				return
			}
			fmt.Print(string(decryptedMessage))
		}
	}()

	clientWriter := bufio.NewWriter(clientConn)
	inputBuffer := make([]byte, 2048)
	for {
		bytesRead, readInputErr := os.Stdin.Read(inputBuffer)
		if readInputErr != nil {
			if readInputErr != io.EOF {
				clientLogger.Printf("Error reading input: %v", readInputErr)
			}
			return
		}

		encryptedInput, encryptionErr := secureData(inputBuffer[:bytesRead], clientKey)
		if encryptionErr != nil {
			clientLogger.Printf("Error encrypting input: %v", encryptionErr)
			continue
		}

		lengthBuffer := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBuffer, uint32(len(encryptedInput)))
		_, writeLengthErr := clientWriter.Write(lengthBuffer)
		if writeLengthErr != nil {
			clientLogger.Printf("Error writing length to server: %v", writeLengthErr)
			break
		}

		_, writeDataErr := clientWriter.Write(encryptedInput)
		if writeDataErr != nil {
			clientLogger.Printf("Error sending encrypted data to server: %v", writeDataErr)
			break
		}
		clientWriter.Flush()
	}
}
