Secp256k1 multiset module
=========================

Abstract
--------

This module allows calculating a cryptographically secure hash for a
set with the properties:

* The order of the elements of the set does not effect the hash
* Elements can be added to the set without recalculating the entire set

Or mathematically, it is:

* Commutative: H(a,b) = H(b,a)
* Associative: H(H(a,b),c) = H(a,H(b,c))

Hence it behaves similar to XORing the hashes of the individual elements, 
but without the cryptographic weakness of XOR.

Motivation
----------

The multiset can be used by cryptocurrencies to cheaply create and 
maintain a commitment to the full UTXO set as proposed by Pieter Wiulle [1]

It can also be used with a bucketed approach to enable cheap UTXO-proofs as
proposed by Tomas van der Wansem [2]

Usage
-----

    // Construct a multiset of (data1,data3)

    unsigned char data1[100],data2[150],data3[175];
    ...
    secp256k1_multiset x,y;
    secp256k1_multiset_init  (context, &x);

    // add all 3 data elements
    secp256k1_multiset_create(context, &y, data1, sizeof(data1));
    secp256k1_multiset_add   (context, &x, &y);
    secp256k1_multiset_create(context, &y, data2, sizeof(data2));
    secp256k1_multiset_add   (context, &x, &y);
    secp256k1_multiset_create(context, &y, data3, sizeof(data3));
    secp256k1_multiset_add   (context, &x, &y);

    // remove data2
    secp256k1_multiset_create(context, &y, data2, sizeof(data2));
    secp256k1_multiset_remove(context, &x, &y);

    // convert to hash
    secp256k1_multiset_finalize(context, hashBuffer, &x);

Algorithm
---------

The implementation uses trial-and-increment [3] to convert the hash into
point on the secp256k1 curve which serves as multiset. The curve's 
group operations are then used to add and remove multisets. 
Associativity and Commutativity then follow.

Security
--------
The hash is secure against collision attacks.

The algorithm used is susceptible to timing attacks. Therefore it does
not securely conceal the underlying data being hashed.

For the purpose of UTXO commitments this is not relevant.


References
----------

[1] https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2017-May/014337.html

[2] https://lists.linuxfoundation.org/pipermail/bitcoin-ml/2017-September/000240.html

[3] https://eprint.iacr.org/2009/226.pdf

