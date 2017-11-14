This writeup is from a semester-long cryptography project wherein our group was attempting to program a simple file and group server setup from scratch while making use of the Java BouncyCastle encryption library. The purpose of the reports was to justify to the instructor our programming choices and security decisions. This report was crafted as part of a group with two other students. I selected phase 4 as a sample because, referring back to the log, I apparently crafted at least 90% of this paper.

## Phase 4 Overview

In this phase of the project, we have lost several of our initial trust assumptions and will have to take action to retain security in the face of these changes. We can no longer assume that an adversary monitoring communications will be passive; they are now a potential active attacker and we must be able to recognize reordered, replayed and modified messages. File servers are now untrusted and can leak files to users who do not have the appropriate group permissions or to any other outside entity. They may also attempt to steal tokens and use them on other file servers. Fortunately, some of the security measures implemented in phase 3 will easily cover these circumstances, and others will require only small modifications.

We will be using many of the same cryptographic primitives as were used in the prior phase, the justification for which will be covered here. We will continue to use symmetric cryptography to send messages over a secure channel, and we will additionally use it to encrypt files before upload. For symmetric crypto we will use AES with 256 bit keys in CBC mode with PKCS5 padding. We've based a number of keysize decisions on the NIST publication "Transitions: Recommendation for Transitioning the Use of Cryptographic Algorithms and Key Lengths", which recommends secure algorithms and keysizes for government documents. The keysize of 256 is approved there for encryption and decryption (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar1.pdf, pg 4). We selected CBC because we will not be using parallel processing and for it's simplicity. Padding is necessary when using CBC mode in order to guarantee input is divisible by the internal block size. When we use an IV, we will use one of size 16 bytes, but it will not increase to be used as a counter in this phase. Instead we will use a pair of integer counters. We want a larger IV to decrease the chance of IV reuse, but since in CBC the IV is XORed with the internal AES cipherblock, we're capped at AES's internal blocksize (16 bytes). We will do hashes using the SHA-256 algorithm. We will also use a 256 bit AES key to perform SHA-256 based HMACs to verify authenticity. The keysize for HMACs is based upon the recommendations of RFC 2104, which minimally suggests a key size of size L (the size of the output, 256 bits for SHA-256) and says that longer keys "are acceptable but the extra length would not significantly increase the function strength" (https://tools.ietf.org/html/rfc2104#section-3).

We will continue to use public key cryptography solely for the formation of digital signatures, using RSA with 2048 bit keys. We chose to use a 2048 bit key for RSA because that is the minimum size recommended by NIST for digital signatures (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar1.pdf, pg 6). Digital signatures in RSA provide guarantees of integrity and authenticity (as well as non-repudiation, but we are not relying upon that guarantee). Digital signatures guarantee integrity because, if any change is made to the encrypted data, it will not be possible to decrypt it to legible data using the public key. They guarantee authenticity because the signature can only be made by someone who has the private key. As in the previous phase of the project, we will only ever use an RSA keypair for signing and checking the signature of one type of data. As before, the group server's keypair will still be used for user tokens. But now, the file server's keypair will be used for Diffie Hellman public keys.

Setup of secure channels is still based upon the same secure handshake protocols. The client's connection with the file server will implement Diffie Hellman, using the parameters from the 2048 group of RFC3526 (https://www.ietf.org/rfc/rfc3526.txt). The 2048 group is the minimum size recommended by NIST for Diffie Hellman key agreements (https://www.ietf.org/rfc/rfc3526.txt, pg 9). Diffie Hellman is assumed to be mathematically hard to break, requiring that the hard problem of discrete logarithms be solved to derive g^su from g^s and g^u. In this phase of the project we will implement signed Diffie Hellman to protect against man-in-the-middle attack (see T5). The connection with the group server will be established via the Secure Remote Password protocol (henceforth SRP) using the parameters specified in the 2048 group from RFC5054 (https://www.ietf.org/rfc/rfc5054.txt). Since SRP is based upon Diffie Hellman, we kept with the same group size for both agreements. SRP is based upon Diffie Hellman, but uses a salted hash of the user's password as part of the exponent on the final shared secret, ensuring that both sides have knowledge of the password without requiring it be sent on the unsecured channel. The implementation of SRP has not changed from the prior phase of the project.

### A Key for Diagrams
*All diagrams used in this paper will accord with the following key*
- A+B+C : data that is concatenated in string form, in the order specified. If any item within the list is itself a list, that list will be appended in lexographical order.
- H(A) : A is hashed using SHA-256
- HMAC(A)K : A HMAC of A computed using key K and SHA-256
- {A}K,IV : A is encrypted using AES with a 2048 bit key, using IV as the nonce or initialization vector in CBC
- *data* : data is stored to disk long term, not just used for this exchange 
- \[A\]K^-1 : A is signed using SHA-256 RSA with the private key corresponding to K (2048 bits)

## Implementation Details

### T5 Message Reorder, Replay, or Modification

Since the adversary is no longer simply passively monitoring communications but is now also actively intercepting, modifying and replaying them, some changes will have to be made to the protocols we had previously implemented. In the previous phase of the project, after setting up a secure channel, we relied on an HMAC over the message (using the key types and algorithms described in the overview) to ensure that modifications can be detected. If a message and its HMAC did not match, the message was dropped. In this phase, we will be expanding the HMAC such that a single HMAC is done over the encrypted message, the IV, and a message counter for the sender (more on that later). This concatenation will be computed as a byte array created by copying the byte arrays for the ciphertext, IV, and counter (created by making a BigInteger object of the counter and then using that object's toByteArray function) sequentally into a byte array the size of the sum of the component arrays.

Public RSA Keys are transmitted over an insecure channel, but the receiver of the key verifies the key's hash with the key's owner in person, so an attacker is not able to falsify information here. The SRP exchange requires setup messages to be sent or received in a certain order or the connection will terminate. An active attacker monitoring the messages sent in SRP would be unable to implement a man in the middle attack because they would lack the value of the verifier, which is based upon the client's password and a random salt. They could lead the client and server to generate non-matching keys but would be unable to produce the verifier message or to hijack the connection to the server or client used in the creation of the shared secret from the public keys. Thus, SRP is protected against modification. Because of the set message ordering, we are protected against replay and reordering within a session. And since in every new connection the client and server generate new random values for their SRP private keys, reusing old messages across sessions would not allow an attacker to do anything useful.

The one place where we are vulnerable to message modification in the current implementation is Diffie Hellman, which is used to set up a connection from the client to the file server. Currently (as of Phase 3), an attacker can intercept the DH public key sent by the client and exchange back a DH public key as if they were a server, simultaneously forming their own connection to the legitimate file server. This man-in-the-middle attack would allow an attacker to read all traffic after the handshake is formed. To prevent this, we will alter the protocol into signed Diffie Hellman. The file server's RSA keypair, which was previously used to sign a random challenge, will instead be used to make a signature over their Diffie Hellman public key when they respond to a user. This protects against the man-in-the-middle attack because the attacker can no longer forge a connection pretending to be from the server. They can set up their own connection to the server, and they can drop traffic from the client to the server, but there is no way to forge the relay required for a man-in-the-middle attack. Just as in SRP, the Diffie Hellman protocol as implemented requires messages to be sent in a certain order, preventing replay and reordering when attempting to establish a session. Moreover, since the file server and client generate new random challenges each time they set up Diffie-Hellman or SRP, the attacker cannot replay a sequence of messages to establish a connection and repeat an action in a new session; the server will close the connection if the random challenge is not correct.

That leaves only message reordering and replay within and between secured sessions. Since we will use the shared secret generated via SRP or Diffie Hellman to generate a pair of 256 bit AES keys, one each for encryption and authentication, messages will only be valid within the session they were created for (these keys will be generated by doing a SHA-256 hash upon the secret concatenated with the signifier "Encryption" and "Authentication" respectively). Within a session, we will use a pair of counters to prevent reordering and replay. In the prior phase, IVs were required to be strictly increasing, which prevented old messages from being replayed or reordered. However, it would not allow for a client to respond to the server asynchronously. If a client sends two requests before receiving a response from the server, both the client and server would end up in a bad state where the IV value received would not match what was expected. To solve the problem of an asynchronous client, we will instead maintain two session counters - one for the client and one for the server - and use random IVs (generated via secure random). Both the client and server counter will begin at zero. When a message is sent, the sender will increment their own counter and send the incremented counter along with the message. The receiver will check that the counter received is strictly greater than the currently stored counter for the other party. The validity of the counter is protected by the HMAC over the message, counter and IV. Since the counters must be strictly increasing and cannot be disassociated with the encrypted message without invalidating the HMAC, there is no way to reorder or replay a message within a secured session. 

---
### Diagram 1
Setting up signed Diffie Hellman. The user has already requested the file server's public key, verified and stored it. In this exchange Cuu is the user's local counter and Cus is the server's copy, Csu is the server's local counter and Css is the client's copy.

| User | Transmitted | File Server|
|:------------|:-----------:|-------------:|
| *Kf* | | *Kf, Kf^-1* |
| Initialize DH parameters | | |
| Generate DH Keys: u (private) and (g^u)%p (public) | | |
| | (g^u)%p -> | |
| | | Generate DH Keys: s (private) and (g^s)%p (public) |
| | <- (g^s)%p, [(g^s)%p]Kf^-1 | |
| Check signature using Kf | | |
| shared secret SS=calculate agreement(u, (g^s)%p) | | shared secret SS=calculate agreement(s, (g^u)%p) |
| Ke = genAESKey(SS+"encryption", 256) | | Ke = genAESKey(SS+"encryption", 256) |
| Ka = genAESKey(SS+"authentication", 256) | | Ka = genAESKey(SS+"authentication", 256) |
| set Cuu=0, Csu=0 | | set Cus=0, Css=0|
| generate random IV , 256 bit challenge *R1* | | |
| Increment Cuu+1 | | |
| | ({R1}Ke,IV), IV, Cuu, HMAC(({R1}Ke,IV)+IV+(Cuu))Ka -> | |
| | | verify Cuu>Cus, set Cus=Cuu |
| | | verify HMAC |
| | | decrypt message |
| | | generate random IV', 256 bit challenge R2 |
| | | Increment Css+1 | 
| | <- ({R1, R2}Ke,IV'), IV', Css, HMAC(({R1, R2}Ke,IV')+IV'+(Css))Ka | | 
| verify Css>Csu, set Csu=Css | | |
| verify HMAC | | |
| decrypt message | | |
| Check R1 recieved = R1 sent | | |
| generate random IV" | | |
| Increment Cuu+1 | | |
| | ({R2}Ke,IV"), IV", Cuu, HMAC(({R1}Ke,IV")+IV"+(Cuu))Ka -> | |
| | | verify Cuu>Cus, set Cus=Cuu |
| | | verify HMAC |
| | | decrypt message |
| | | Check R2 recieved = R2 sent |

---

### T6 File Leakage
The major complication of untrusted file servers is that, clearly, the file servers must have access to the files. But, if files are stored as plaintext in the file server, a malicious administrator can distribute those files to other unauthorized principles. This would defeat the entire design of the system, which is built around the idea that only users within the group a user has uploaded a file to will be able to access those files. It even defeats the more basic assumption that only users of the system will be able to access the files. It would also be possible for files to be maliciously altered since they are stored in plaintext, as there is no means of verifying that files are unchanged. This creates a situation where a user is unsure if the files retrieved from the server are actually files uploaded by a group member and where no file uploaded can be assumed to be private in any sphere.

The complexity of implementing a solution to this security threat is that the file server and group server are relatively isolated. Only an individual file server knows what files have been uploaded to a group. Only the sum total of group members know what file servers have been granted access to group files. And only the group server tracks who are the members of a group. For this reason, it is impossible for a the deletion of a group member to trigger a change in encryption for all files on all file servers. Additionally, since any member of a group can download any file, it is reasonable to assume that a member removed from a group already has downloaded all of the group's files and that we don't care if he or she can still decrypt leaked group files, provided the leaked files were uploaded before he or she was removed from the group. We will only focus on providing forward secrecy: a member removed from a group cannot decrypt any messages uploaded after he or she was removed. In addition, any other party unaffiliated with the group will be unable to decrypt any files and any current group member will be able to decrypt all files.

In order to implement this policy, the group server will create and store for each group a random AES base encryption key. It will implement a versioning system that decrements from 1,000,000, which will cap the number of versions, and thus, the number of members that can be removed from a group, at 999,999. This number was derived by a simple timing test of SHA-256 on a modern laptop: we found that 100,000 chained hashes took about 125 milliseconds, a million hashes took around 700 milliseconds and ten million hashes took about 6,500 milliseconds. A million seemed like a reasonable compromise where the delay will not be noticeable for the users but where the cap on versions will not likely be an issue for most groups. For this purpose the group server will store the base key (Kgbase), current version number (v), and the encryption key for that version (Kge). Kge is calculated upon key generation or an update to v by performing a chained SHA-256 hash upon the base key v times (see diagram 3). When a user requests a user token, the group server will return along with that token, a group-key pairing for each of the user's groups, linking the group name with the current Kge and version for that group. These will be stored by the user and will remain valid for the entire user session (see diagram 2). When a user wants to upload a file to the file server, they will encrypt the file locally using Kge and a randomly generated IV. They will send to the file server the ciphertext, IV and version number. The file server will store the file's metadata in the ShareFile object, which will have the IV and version number fields added to it, and will save the ciphertext to disk as a file. When a client downloads a file, they will first check the version number. If the version number (v") is greater than their stored version number (v) -- i.e. the file was stored using an older version of the group's key -- they will hash Kge v" - v times in order to obtain the correct key for that file. Using the generated key and the provided IV, they will decrypt the downloaded ciphertext (see diagram 4).

The security of this implementation depends upon the property of preimage resistance in SHA-256. Knowing the most recent key before they were removed from the group will not enable a slighted group member to recover any subsequent keys without relying upon a brute-force attack, because it will require reversing some number of hashes. And, since the file server never comes in contact with the actual keys or plaintext, it has no means with which to attack the stored ciphertexts besides a brute force attack on AES.

---
#### Diagram 2
Fetching a user token and group keys from the group server. The group server and user have already set up a secure connection via SRP.
Kgs and Kgs^-1 are the Group server's RSA keys. Ke is the session encryption key and Ka is the session authentication key. In this exchange Cuu is the user's local counter and Cus is the server's copy; Csu is the server's local counter and Css is the client's copy.

| User | Transmitted | Group Server|
|:------------|:-----------:|-------------:|
| *Ke, Ka, Cuu, Cus*| | *Kgs, Kgs^1, Ke, Ka, Csu, Css* |
| | | *For each group: name, Kbase, Kcurrent, v* |
| Message m=Fetch_token(user u, recipient string r) | | |
| generate random IV, Increment Cuu+1 | | |
| | ({m}Ke,IV), IV, Cuu, HMAC(({m}Ke,IV)+IV+(Cuu))Ka -> | |
| | | verify Cuu>Cus, set Cus=Cuu |
| | | verify HMAC |
| | | decrypt message |
| | | Verify that u is the user who set up the secure connection |
| | | Generate token=(groupserver_ID, expiration time=t, u, list of u's groups, r) |
| | | Generate hash=H(u+'‡'+groupserver_ID+'‡'+t+'‡'+r+'‡'+groups in lexographical order) |
| | | Generate signature=[hash]Kgs^-1 |
| | | Generate user copies of group keys: (name, Kbase=Kcurrent, Kcurrent, v) |
| | | Generate list of group-key pairings: GKP_list |
| | | Message m=OK(token, signature, GKP_list) |
| | | generate random IV', Increment Css+1 |
| | <- ({m}Ke,IV'), IV', Css, HMAC(({m}Ke,IV')+IV'+(Css))Ka | |
| verify Css>Csu, set Csu=Css | | |
| verify HMAC | | |
| decrypt message | | |
| Verify token signature | |
| Store *token* | |
| Store *GKP_list* | | 


#### Diagram 3
Removing a user from a group and the subsequent update to Kge. See notes from diagram 2 for terminology.

| User | Transmitted | Group Server |
|:------------|:-----------:|-------------:|
| *Ke, Ka, Cuu, Cus*| | *Kgs, Kgs^1, Ke, Ka, Csu, Css* |
| | | *For each group: name, Kbase, Kcurrent, v* |
| Message m=RemoveUser(group g, user u, token a) | | |
| generate random IV, Increment Cuu+1 | | |
| | ({m}Ke,IV), IV, Cuu, HMAC(({m}Ke,IV)+IV+(Cuu))Ka -> | |
| | | verify Cuu>Cus, set Cus=Cuu |
| | | verify HMAC |
| | | decrypt message |
| | | Verify that a has the permissions to remove u from g |
| | | Remove u from g |
| | | *v=v-1* |
| | | K=Kbase; for(i=0; i<v; i++) {K = h(K)} |
| | | *Kge=K* |
| | | Message m=OK() |
| | | generate random IV', Increment Css+1 |
| | <- ({m}Ke,IV'), IV', Css, HMAC(({m}Ke,IV')+IV'+(Css))Ka | |
| verify Css>Csu, set Csu=Css | | |
| verify HMAC | | |
| decrypt message | | |

#### Diagram 4
Encrypted File Upload + Download. See notes from diagram 2 for terminology.

| User | Transmitted | File Server |
|:------------|:-----------:|-------------:|
| *Ke, Ka, Cuu, Cus*| | *Ke, Ka, Csu, Css* |
| *GKP_list:(name, Kbase, Kcurrent, v) per group* | |
| generate random IVfile | | |
| ciphertext c={file}Kge,IVfile | | |
| Message m=UPLOAD(filename, c, IVfile, v, groupname, token) | | |
| generate random IV, Increment Cuu+1 | | |
| | ({m}Ke,IV), IV, Cuu, HMAC(({m}Ke,IV)+IV+(Cuu))Ka -> | |
| | | verify Cuu>Cus, set Cus=Cuu |
| | | verify HMAC |
| | | decrypt message |
| | | Check that token is valid for group |
| | | Save *filename, IV, v, group* in Sharefile |
| | | Save *ciphertext* to disk as filename |
| | | Message m=OK() |
| | | generate random IV', Increment Css+1 |
| | <- ({m}Ke,IV'), IV', Css, HMAC(({m}Ke,IV')+IV'+(Css))Ka | |
| verify Css>Csu, set Csu=Css | | |
| verify HMAC | | |
| decrypt message | | |
| Message m= DOWNLOAD(filename, group g, token)| | |
| generate random IV, Increment Cuu+1 | | |
| | ({m}Ke,IV), IV, Cuu, HMAC(({m}Ke,IV)+IV+(Cuu))Ka -> | |
| | | verify Cuu>Cus, set Cus=Cuu |
| | | verify HMAC |
| | | decrypt message |
| | | Check that token is valid for group g |
| | | Check that filelist contains an entry for filename belonging to group g |
| | | Message m=(ciphertext, version v", IV") |
| | | generate random IV', Increment Css+1 |
| | <- ({m}Ke,IV'), IV', Css, HMAC(({m}Ke,IV')+IV'+(Css))Ka | |
| verify Css>Csu, set Csu=Css | | |
| verify HMAC | | |
| decrypt message | | |
| if (v"-v>0) {Ktemp=Kge; for(i=0; i<(v"-v); i++) {Ktemp = h(Ktemp)}}|
| else {Ktemp=Kge}|
| file=decrypt(ciphertext, Ktemp, IV") |
| *file* |

---

### T7 Token Theft
As token exchanges are implemented currently, a token for a user is valid at any file server. This means that when a user uses their token to get access to any file server functionality, that file server could then store the token and pose as the user to any other file server. They could not do this indefinitely, as the tokens include an expiration time set to 25 hours, but during that window any other file server would see the token as valid. Obviously, in our new model of untrusted file servers, the possibility of servers stealing users' identities and then gaining illegitimate access to documents on other servers is troubling.

Fortunately, this is a fairly simple fix. A server receiving a token already checks the validity of several token fields and checks it against a signature contained inside the token. We will include a field inside the token to identify the intended recipient file server, which a file server will check against upon receiving a token. Servers already possess a unique piece of identifying information: their RSA keypair. We leverage this by representing the identity of the server as the SHA-256 hash of the file server's public key converted to its String representation. If a server receives a token whose recipient server field does not match the server's identity, they will reject the token as invalid. The user will create this String representation from the file server's public key and send it to the group server when requesting a token. This has the added benefit that a user can only request a token to access a file server whose public key they have already confirmed. The group server, since it requires no knowledge of file servers, will perform no checks on the information. It will simply assign the recipient's identity into the correct field of the token and then create the signature. 

The signature will now be computed by concatenating the string representations of the following UserToken fields in this order: UserID, origin server, expiration time, recipient server, followed by the groups sorted in lexicographic order. The fields, along with each individual group, will be separated by a sentinel value, "‡", which group and userIDs will not be allowed to contain. The fully concatenated string will be converted to an array of bytes using UTF-8 encoding, hashed and signed with the group server's private key (See diagram 2). The signature is checked by using the group server's public key to retrieve the original hash from the signature and then comparing that to a hash computed locally using the same elements of the UserToken in the same order.

This solution does not prevent a server from accepting an invalid token. Technically, a malicious server could perform any action upon the files uploaded, regardless of the user tokens submitted. What this prevents is good-actor file servers being tricked by a malicious file server who has stolen user tokens. As in phase three, the digital signature guarantees integrity and authenticity of the token as linked to the group server's RSA public key. There is no feasible way for it to be forged or altered, so there is no means for a server to alter any field within the token, including the new recipient server field, in order to misuse the token on another server.

## Interplay of Security Features and Conclusions

These changes in the program's implementation will require the creation of no new cryptographic primitives, only the alteration of data structures and functions already used within our framework. Validating tokens with a recipient RSA public key and sentinel values will require small alterations to the generateTokenHash function for signing and verifying. Our Encryption Handler class, used to store encryption and authentication keys and do encryption/decryption and authenticity verification, will be split into Message and File Encryption Handlers. The base Encryption Handler that both classes extend will be built to provide for randomized IVs. The Message Encryption Handler will also be edited to allow for the two counters to be tracked and to include a sentinel value within the HMACs but will be otherwise unaltered. The File Encryption Handler class will be used to encrypt and decrypt files and to store base and current key values. It will also be able to generate new keys (the base and current version key) for the server, create a copy containing just the current version key to send to the user, and decrypt files encrypted with a key whose version is higher than the current version (by hashing over the current key). We will use a second class called Groupkey Pairing to group these File Encryption Handlers with the groupnames for storage on both the group server and locally by the client. The group server will store the Groupkey Pairings inside the grouplist instead of the list of groupnames. The user will store them in memory inside the group client until they need to fetch a particular group's encryption handler for encryption or decryption. The changes to Diffie Hellman will require that the file server to sign their DH public keys using their RSA private keys, a functionality already provided for by RSA helper's signBytes method (a byte array of the keys can be extracted using the key's native getEncoded function), and that the client verify the the file server's signature (functionality also provided for in RSA helpers, checkSignature).

None of the changes made in this phase of the project will compromise the security assumptions of the prior project phase. We make no changes to the secure handshake using SRP and the signed variant of Diffie Hellman provides no further information to an adversary that would allow them access to the shared secret. Generation of session keys from our shared secret remains the same. Our encryption has changed slightly in the details: we use a randomized IV for every message and a single HMAC over all of the fields (encrypted message, IV and counter). The way counters will be incremented and checked within a secured session will prevent message modification, reordering and replay in the same way incrementing IVs did in the prior phase. The channel to the group server is still assumed to be secure and the group server absolutely trusted, so storing group keys and transferring them between users and the group server after setting up the secure channel is as secure as storing the group server's own private key on the server and transferring other encrypted messages between the two parties. Adding a single field to the user token will not change the security of checking against a group server's signature for authenticity. 

Via an unchanged SRP implementation, we are sure that T1 is still accounted for. Via the fact that the changes to the Token and signature will not substantially change the workings of checking the token for validity, we are sure that T2 is as secure as it was in the prior phase. Our change to Diffie Hellman still requires the file server to sign a message to verify its authenticity to the client. Before it signed a random challenge, but now it signs its DH public key. Since only the file server can create the signature, T3 is still maintained. Finally, T4 relied on both of our handshake protocols, DH and SRP, and encryption within a session using the session key. We have already addressed how our modifications to the handshakes maintain their security. The session keys are also unchanged and having a single HMAC over the message, IV and counter is as secure as having separate HMACs for messages and IVs.
