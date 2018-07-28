# Protocol

A, B: clients, S: rendezvous server

A logs in to the server with a chosen name:

    A -> S:  hmac(nonce + name) + nonce + name

The server responds to A with an empty message:

    S -> A:  hmac(nonce) + nonce

Later, B logs in to the server with the same name:

    B -> S:  hmac(nonce + name) + nonce + name

The server responds to B with an empty message:

    S -> B:  hmac(nonce + name) + nonce

Now the server pairs the two clients A and B:

    S -> A:  hmac(nonce + B) + nonce + B
    S -> B:  hmac(nonce + A) + nonce + A

And hole-punching starts between A and B:

    A -> B:  0x80
    A -> B:  0x80
    ...

    B -> A:  0x80
    B -> A:  0x80
    ...

Upon receiving a ping, A (B) responds to B (A) by a pong message:

    A -> B:  0x81
    B -> A:  0x81

Afterwards A and B communicate peer-to-peer.
