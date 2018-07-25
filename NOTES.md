# Protocol

A, B: clients, S: rendezvous server

First A and B login to the server with a chosen name:

    A -> S:  hmac(nonce + name) + nonce + name
    B -> S:  hmac(nonce + name) + nonce + name

Server pairs clients with the same name and sends peer's address to the clients:

    S -> A:  hmac(nonce + B) + nonce + B
    S -> B:  hmac(nonce + A) + nonce + A

A and B send ping (0x80) messages to their peers to punch holes on NATs:

    A -> B:  0x80
    A -> B:  0x80
    ...

    B -> A:  0x80
    B -> A:  0x80
    ...

A and B respond to ping by a pong (0x81) message:

    A -> B:  0x81
    B -> A:  0x81

Afterwards A and B communicate peer-to-peer.
