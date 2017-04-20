# NSProject
- Authors: Zhou Xuexuan (1001603) Wu Zheyu (1001780)
- Date: 20/04/2017
## Purpose of program
The purpose of the program is to simulate uploading text file and image to server and before uploading, we need to check whether the server is the true server.
## How to compile your program
1. Download the code and unzip.
2. In each java file change the rootpath (filepath in ClientAES for both img and file) to your working directory
3. If you are trying this on the same computer, you can keep the hostname at client side as 127.0.0.1. If you are simulating it on two different computers, change the hostname into the IP of the computer which runs the server.
4. For testing fake server, you may change the "CA.crt" into "CAfake.crt".
5. For testing uploading different size of the text file, you may change the text file in filepath to (smallFile.txt, medianFile.txt or largeFile.txt). As for the img, we only implement bmp type, you may just try it with the globe.bmp inside.
## What exactly does the program do
##### ServerSide
1. Keep running and receiving connections from clients.
2. Once connected, handshake with it.
3. If handshake seccessed, receiving the file from client.
4. Decrypting the file and store it.
5. Wait for another connection.
##### clientSide
1. Check whether the server is the correct server you are to uploading file.
2. If it is, upload the encrypted files. If not, disconnect from it.
