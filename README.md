# Design of an end to end messaging system like WhatsApp

## Commands
* `signup username password`
* `signin username password`
* `LIST`
* `JOIN <GROUPNAME>`
* `CREATE <GROUPNAME>`
* `<SEND> <USERNAME> <MESSAGE>`
* `<SEND> <USERNAME> FILE <FILEPATH>`
* `<SEND> GROUP <GROUPNAME> <MESSAGE>`

## Internal Messages
* Signup message from client to server: `signup username password ip:port`
* Signin message from client to server: `signin username password ip:port`
* Response for group list from server to client: `list1:<number of members in list 1>,list2:<number of members in list 2>...`
* Response for join group to server
  - `list`
  - `join groupname username`
  - `key:groupname`
* Response from server to client:
  - `group1:[peer1,peer2..],group1:[peer1,peer2..],...`
  - `Response string`
  - `key (sent as byte and need to be recieved as byte without encoding decoding)`
* Request for client ip and port from client to server: `client_info:username`
* Response for client ip and and port from server to client: `ip:port`
* Request for group clients ip and port from client to server: `group_info:groupname:username`
* Response for group clients ip and port from server to client: `ip:port;ip:port;ip:port;...`

<!-- ## Useful info
* IP, Port of server is passed as colon separated command line argument in both client and server program.
* IP, Port of client's server needs to be passed additionally, separated by colon.
* Structure of dictionary to store user information.
    `user_info {
        "user_name": {
            "pass": "abc",
            "IP": "",
            "port": "",
            "active": true/false,
            "groups": [group1, group2]
        }
    }`
* Structure of dictionary to store group information.
    `group_info {
        "group_id1": {
            "owner": "userid1", 
            "peers": ["userid1", "userid2"]
        }
    }`
* On signing in, pass client ip and port from client and update it in server side.
* On every request from client to the server, the client is expecting "Error" as the first word in case of any error. Example, "Error:User already exists".
* Sample working of DES. While sending key to other client, also send iv<br />
    d1 = DES()<br />
    key = d1.generate_key_DHK("123")<br />
    plaintext = "abcd"<br />
    print(plaintext)<br />

    ciphertext, uv = d1.encrypt(plaintext, key)<br />

    print(ciphertext)<br />

    decrypted_text = d1.decrypt(ciphertext, key, iv)<br />
    print(decrypted_text)<br />
* For group encryption decryption-<br />
    key= Save the key sent in bytes as is  <br />
    
    plaintext = "abcd"<br />
    print(plaintext)<br />

    ciphertext, uv = d1.encrypt(plaintext, key)<br />

    print(ciphertext)<br />

    decrypted_text = d1.decrypt(ciphertext, key, iv)<br />
    print(decrypted_text)<br />
     -->


## Bugs
* Need to manually stop all threads on pressing Control+c to exit program.

## Fixed Bugs
* Invalid command by user.
* Resusing port number in socket connection.
