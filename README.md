# cool Project

## Setup
### generate keypars for client and server
For generating the keypars for client and server the class `GenerateKeypairApplication` is provided
Generate the jar-with-dependencies by running `mvn clean package -DskipTests` and then run the Keygeneration for 
client and server respectively with the following command:
`java -cp target/PA2-1.0-jar-with-dependencies.jar util.GenerateKeypairApplication <client|server> <optional: curve algorithm>`
This will create the files `resources/pa2/client/ClientECCKeyPair.sec`, `resources/pa2/client/ServerECCPubKey.txt` and `resources/pa2/server/ServerECCKeyPair.sec`.

### populate the user database on the server
To populate the `userdatabase.txt` file in `resources/pa2/server` one can either put in the entries manually or
use the class AddUserApplication to add a users. The application asks for userid, password and public key, but
will also just generate any of those if the input is left empty.
Usage: `java -cp target/PA2-1.0-jar-with-dependencies.jar util.AddUserApplication`

# task PA2
**Goal**: to provide authentication and agreement on cryptographic configurations
for the dynamic establishment of related security association parameters
(including cryptographic configurations).

To achieve this goal, SHP must incorporate complementary cryptographic
solutions, including:
- Password-based encryption methods
- Public-key cryptography
- Digital signatures
- Diffie-Hellman key agreement

## phase 1

### Authentication Requirements
SHP Phase 1 must provide a strong two-factor authentication solution
for users (using client-side applications) in the interaction with server-side applications

**Client-Side Authentication Mechanisms**
- User Authentication, based on Passwords and Password-Based Encryption Construction
- User Peer-Authentication Guarantees based on the use of Digital Signatures using Public-Key Cryptography (based on ECDSA Digital Signatures)

**Server-Side Authentication Mechanisms**
- Server-Side Peer-Authentication Guarantees based on the use of Digital Signatures using
Public-Key Cryptography (based on ECDSA Digital Signatures)

**Client/Server Mutual Authentication**
- With the above solutions, SHP must provide mutual peer-authentication guarantees,
that ca be controlled by clients and servers

### Confidentiality Requirements

**SHP Phase 1 must provide connection-oriented confidentiality**
- During Clint/Server SHP message exchanges, the critical information that
must be exchanged with confidentiality guarantees will be encrypted using
Password-Based Encryption

### Integrity Requirements
**SHP Phase 1 must provide integrity, with the following guarantees in
considered critical SHP messages**
- Connection oriented message integrity (with no recovery), combining:
  - Use of HMACs for fast message authentication and integrity checking
  - Implicit integrity in messages where digital signatures are used
- Flow integrity is ensured with the use of protected nonces, which are
managed as random, used-use challenges/responses throughout the message
exchanges


### Message-Replay Protection
**SHP Phase 1 must provide anti-message-reply guarantees:**
- Message-replaying countermeasures are based with the required control
of uniqueness of critical messages, with the use of implicit mechanisms
such as nonces, which are managed as random, single-use
challenges/responses during message exchanges, as well as by controlling
the uniqueness of HMACs in the protocol's operation.
- In complementarity, message-exchanges in TCP sessions must be ordered,
by controlling the message-types that will be processed (only-once) in the
correct sequence of message exchanges