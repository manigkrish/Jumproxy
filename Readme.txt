To implement this code, follow the below steps:
1. Create a password txt file to pass as one of the parameters. 
2. Build the code using : go build - o jumproxy jumproxy.go
3. Run the server on reverse proxy mode using the sample command : go run jumproxy.go -k pwdfile.txt -l 2222 localhost 22
4. Run the client using the command (can either use same VM instance and another terminal or another VM instance too): ssh -o "ProxyCommand go run jumproxy.go -k pwdfile.txt 192.168.100.5 2222" kali@localhost
5. Enter the password of the user@connection in the client to access data using the Jumproxy tunnel layer. 
6. Entered commands in the input stream of client are encrypted and sent to server, which then decrypts these commands. (initiateServer, initiateClient and manageConnection functions are used for creation and management of server and client connections)
7. The response from server is then encrypted and decrypted at the client side. (using functions secureData and decodeData)
8. Encryption and decryption happens using the symmetric key, which is generated using the passphrase provided in the password txt file and harcoded salt value(generated using the function deriveKey)
9. For detailed log references, refer to JumproxyLog.log file (which is created in the same directory).
