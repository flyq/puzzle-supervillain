# puzzle-supervillain

**DO NOT FORK THE REPOSITORY, AS IT WILL MAKE YOUR SOLUTION PUBLIC. INSTEAD, CLONE IT AND ADD A NEW REMOTE TO A PRIVATE REPOSITORY, OR SUBMIT A GIST**

Trying it out
=============

Use `cargo run --release` to see it in action

Submitting a solution
=====================

[Submit a solution](https://xng1lsio92y.typeform.com/to/qKny5btM)

[Submit a write-up](https://xng1lsio92y.typeform.com/to/jBCFIpGK)

Puzzle description
==================

    |___  /| | / / | | | |          | |
       / / | |/ /  | |_| | __ _  ___| | __
      / /  |    \  |  _  |/ _` |/ __| |/ /
    ./ /___| |\  \ | | | | (_| | (__|   <
    \_____/\_| \_/ \_| |_/\__,_|\___|_|\_\

Bob has been designing a new optimized signature scheme for his L1 based on BLS signatures. Specifically, he wanted to be able to use the most efficient form of BLS signature aggregation, where you just add the signatures together rather than having to delinearize them. In order to do that, he designed a proof-of-possession scheme based on the B-KEA assumption he found in the the Sapling security analysis paper by Mary Maller [1]. Based the reasoning in the Power of Proofs-of-Possession paper [2], he concluded that his scheme would be secure. After he deployed the protocol, he found it was attacked and there was a malicious block entered the system, fooling all the light nodes...

[1] https://github.com/zcash/sapling-security-analysis/blob/master/MaryMallerUpdated.pdf
[2] https://rist.tech.cornell.edu/papers/pkreg.pdf

# Write ups

## Early attempts
When I got this question, I didn't know where to start.

I tried running `cargo run --release`, and as expected, an assert error occurred.

Then I browsed the source code and found that it mainly used things related to the `ark_bls12_381` curve, and then looked at the relevant information provided, two English papers. I couldn't read it after just looking at the `title` and `abstract`. Unfortunately, cryptography papers are often too long for me and I can't grasp the key points. But I vaguely know that this is something related to `BLS signature aggregation` and `rogue key attacks`.

I'm starting to feel the pain. When I was learning ECC in the past, the difficulty of Pairing-related topics was too high for me, so I skipped it. As a result, my current understanding of BLS pairing is only a black box that that can provide method like $e(a G_1, b G_2) = e( G_1, G_2)^{ab}$, I have no idea what's under the hood.

Well, I have to strengthen my understanding of BLS. I found some information, such as Ben's excellent article [BLS12-381 For The Rest Of Us](https://hackmd.io/@benjaminion/bls12-381), which also quotes a lot of great information, such as Vitalik's article [Exploring Elliptic Curve Pairings](https://vitalik.eth.limo/general/2017/01/14/exploring_ecp.html). I have read these two articles several times, but did not understand them. I am thinking that this time I must completely understand the principle of Pairing, for example, at least in the specific scenario of bls12-381.

A few hours went by and eventually I was exhausted by things like field expansion, embeddedness, and so on. I have found that when studying, if you are exposed to too many new concepts at once and cannot connect these concepts (such as deriving formulas), your brain will become increasingly resistant.

I decided to change direction. I want to still treat BLS Pairing as a black box and see if it can solve the problem. As for the principles and theories, I will study them later.

## Background

### BLS Signature aggregation

So I searched for `Rogue-Key Attacks` and found this article [Rogue Key Attack in BLS Signature and Harmony Security](https://medium.com/@coolcottontail/rogue-key-attack-in-bls-signature-and-harmony-security-eac1ea2370ee), and then it is recommended to read [BLS signatures: better than Schnorr](https://medium.com/cryptoadvance/bls-signatures-better-than-schnorr-5a7fe30ea716) to understand the BLS signature, how it works. There was a familiarity to the article that suggested I had read it before, but reading it again allowed me to understand some of the details. In particular, I decided to manually derive it again based on Signature aggregation section:

There are $P_0$, $P_1$, $P_2$, $P_3$ four parties.

$P_0$: secret key $sk_0$, message $m_0$, public key $P_0 = sk_0 \cdot G$, signature $S_0 = H(m_0) \cdot sk_0$

$P_1$: secret key $sk_1$, message $m_1$, public key $P_1 = sk_1 \cdot G$, signature $S_1 = H(m_1) \cdot sk_1$

$P_2$: secret key $sk_2$, message $m_2$, public key $P_2 = sk_2 \cdot G$, signature $S_2 = H(m_2) \cdot sk_2$

$P_3$: secret key $sk_3$, message $m_3$, public key $P_3 = sk_3 \cdot G$, signature $S_3 = H(m_3) \cdot sk_3$

$H$, hash to curve, result is a point.

Verify signature:
- if one by one, $e(G, S_0) = e(P_0, H(m_0))$ and so on.
- if aggregated, $S = S_0 + S_1 + S_2 + S_3$

$$\begin{align*} e(G,S) & = e(G, S_0 + S_1 + S_2 + S_3) \\ &= e(G, S_0)\cdot e(G, S_1)\cdot e(G, S_2)\cdot e(G, S_3) \\ &=e(G, sk_0 \cdot H(m_0))\cdot e(G, sk_1 \cdot H(m_1)) \cdot e(G, sk_2 \cdot H(m_2)) \cdot e(G, sk_3 \cdot H(m_3)) \\ &= e(sk_0\cdot G, H(m_0)) \cdot e(sk_1\cdot G, H(m_1)) \cdot e(sk_2\cdot G, H(m_2)) \cdot e(sk_3\cdot G, H(m_3)) \\ &= e(P_0, H(m_0))\cdot e(P_1, H(m_1)) \cdot e(P_2, H(m_2)) \cdot e(P_3, H(m_3)) \end{align*}$$

Use aggregated signature, we can compute $n-1$ less expensive pairings. ($2n$ vs $n+1$)

Now I figured out that even if different secret keys sign different messages, they can be aggregated.

### rogue key attacks
So what happens with rogue key attacks?
Continue reading the previous article and derive the formula.
Rogue key attacks generally occur when multiple parties sign and aggregate the same message, and the attacker can replace the signed message with the message he wants.

Imagine a scene like this, in consensus, different nodes sign the same block, so $m_0 = m_1 = m_2 = m_3 = m$

The leader $P_4$: secret key $sk_4$, message $m$, public key $P_4 = sk_4 \cdot G$, signature $S_4 = H(m) \cdot sk_4$

Normal Process
- The leader broadcasts block($m$) to all the validators
- The validators send back signatures $S_0, \dots, S_3$.
- The leader broadcasts the aggregated signature $S=S_0+S_1+ S_2 +S_3 + S_4$
- The validators validate $e(G, S) = e(P, H(m))$ with $P=P_0 + P_1+P_2 + P_3+P_4$
- because: $e(G, S) = e(P_0, H(m))\cdot e(P_1, H(m))\cdot e(P_2, H(m)) \cdot e(P_3, H(m))\cdot e(P_4, H(m)) = e(P_0+P_1+P_2+P_3+P_4, H(m))$. 


The malicious leader want to change the block to $m^\prime$
- The leader new a secret key $sk_4^\prime$, with public key $P_4^\prime = sk_4^\prime \cdot G$
- The leader sign the new block($m^\prime$): $S_4^\prime = sk_4^\prime \cdot H(m^\prime)$, so $e(G, S_4^\prime) = e(P_4^\prime, H(m^\prime))$
- The leader public new public key $P_4 = P_4^\prime - (P_0 + P_1 + P_2 + P_3)$
- The leader public new signature $S_4 = S_4^\prime - (S_0+ S_1+S_2+S_3)$
- Other validators aggregate: $S = S_0 + \cdots + S_4 = S_4^\prime$, $P = P_0 + \cdots + P_4 = P_4^\prime$, $e(G, S) = e(G, S_4^\prime) = e(P_4^\prime, H(m^\prime)) = e(P, H(m^\prime))$, So validators think the new block($m^\prime$) is legal.

When the derivation reaches this point, I feel confident that I can solve this puzzle. This is the power of derivation formulas.

$$\begin{align*} e(G, S_4)  & = e(G, S^\prime_4-(S_0+S_1+S_2+S_3)) \\ &= \frac{e(G, S^\prime_4)}{e(G, S_0)\cdot e(G, S_1) \cdot e(G, S_2) \cdot e(G, S_3)} \\ & = \frac{e(P^\prime_4, H(m^\prime))}{e(P_0+P_1+P_2+P_3, H(m))}\end{align*}$$

$$\begin{align*}e(P_4, H(m)) &= e(P^\prime_4 - (P_0 + P_1 + P_2 + P_3), H(m)) \\ &=\frac{e(P^\prime_4, H(m))}{e(P_0+P_1+P_2+P_3, H(m))} \\ &\not ={e(G, S_4)} \end{align*}$$

From above, the $P_4$ can't offer the KOSK(Knowledge Of Secret Key), so the one way to prevent rogue key attacks is requring KOSK.

## Solution

We need to provide `new_key`, `new_proof`, `aggregate_signature`, and make them meet the verification of pok and bls:
```rust
    let new_key = G1Affine::zero();
    let new_proof = G2Affine::zero();
    let aggregate_signature = G2Affine::zero();

    pok_verify(new_key, new_key_index, new_proof);s
    bls_verify(aggregate_key, aggregate_signature, message)
```

Let’s take a look at the contents of `bls_verify` first, because we have just deduced the company and are more familiar with it:
```rust
#[allow(dead_code)]
fn bls_sign(sk: Fr, msg: &[u8]) -> G2Affine {
    hasher().hash(msg).unwrap().mul(sk).into_affine()
}

fn bls_verify(pk: G1Affine, sig: G2Affine, msg: &[u8]) {
    assert!(Bls12_381::multi_pairing(
        &[pk, G1Affine::generator()],
        &[hasher().hash(msg).unwrap().neg(), sig]
    )
    .is_zero());
}
```
The signature is indeed equivalent to:
$S = H(m) \cdot sk$ and $S$ is a point on G2
But the formula for verifying the signature is a bit strange:

$\text{multi\_pairing}([sk\cdot G_1, G_1], [-H(m), sk \cdot H(m)]) = 0$

Well, I can only deal with it as a black box again. $\text{multi\_pairing}([A, B], [-C, D])$ will equal to 0 if $e(A,C) = e(B, D)$

Then we see that an aggregate signature is needed to verify a brand new message:

```rust
    let aggregate_key = public_keys
        .iter()
        .fold(G1Projective::from(new_key), |acc, (pk, _)| acc + pk)
        .into_affine();
    bls_verify(aggregate_key, aggregate_signature, message)
```

This requires rogue key attacks to come into play:
- I new a secret key `let sk = Fr::from(1)`, `sk` can be any `Fr` non-zero element, but for simplicity, I let it be 1.
- the public key `let pubkey = G1Affine::generator().mul(sk).into_affine();`
- I sign the new message: `let sign = bls_sign(sk, message);`
- Then I public the new public key `let new_key = (pubkey - sum_pubkeys).into_affine();`
- At last, the `aggregate_key = new_key + sum_pubkeys = pubkey`, `aggregate_signature = sign`, Of course `pubkey` and `sign` can pass the verification of `bls_verify(aggregate_key, aggregate_signature, message)`.

Then we need to look at pok related
```rust
fn derive_point_for_pok(i: usize) -> G2Affine {
    let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(20399u64);
    G2Affine::rand(rng).mul(Fr::from(i as u64 + 1)).into()
}

#[allow(dead_code)]
fn pok_prove(sk: Fr, i: usize) -> G2Affine {
    derive_point_for_pok(i).mul(sk).into()
}

fn pok_verify(pk: G1Affine, i: usize, proof: G2Affine) {
    assert!(Bls12_381::multi_pairing(
        &[pk, G1Affine::generator()],
        &[derive_point_for_pok(i).neg(), proof]
    )
    .is_zero());
}

fn main() {
    // ...
    let new_key = (pubkey - sum_pubkeys).into_affine();
    pok_verify(new_key, new_key_index, new_proof);
  // ...
}
```
We can see that pok proof is a point on G2. The random number in `derive_point_for_pok` is a fixed number, we can assume it is a. Therefore `proof[i] = a * sk[i] * (i+1) * G2`

According to the previous summary $\text{multi\_pairing}([A, B], [-C, D])$ will equal to 0 if $e(A,C) = e(B, D)$, `pok_verify` will success when $e(sk[i] \cdot G_1, a\cdot(i+1)\cdot G_2) = e(G_1, proof[i])$

How to make `new_key` pass the verification of `pok_verify`? We don’t have the secret key corresponding to the public key `new_key`, but we can make up the correct proof like a signature.

$e(sk[0] \cdot G_1, a \cdot 1 \cdot G_2) = e(G_1, a \cdot sk[0] \cdot 1 \cdot G_2)$

$e(sk[1] \cdot G_1, a \cdot 2 \cdot G_2) = e(G_1, a \cdot sk[1] \cdot 2 \cdot G_2)$

$e((sk[\text{new\_key\_index}] - \sum_{i=0}^{len-1}sk[i]) \cdot G_1, a\cdot(\text{new\_key\_index}+1)\cdot G_2) = e(G_1, a \cdot (sk[\text{new\_key\_index}] - \sum_{i=0}^{len-1}sk[i]) \cdot (\text{new\_key\_index}+1) \cdot  G_2)$

`proof[i]/(i+1) = a * sk[i] * G_2`

`proof = proof[new_key_index] - (new_key_index + 1) * Σ proof[i]/(i+1)`

So, the whole solution is:
```rust
    /* Enter solution here */

    let sk = Fr::from(1); // it can be any Fr element
    let pubkey = G1Affine::generator().mul(sk).into_affine();
    let sign = bls_sign(sk, message);
    let proof = pok_prove(sk, new_key_index);

    // sum_pubkeys = Σ pubkey
    // sum_proofs = Σ (new_key_index + 1) / (i + 1) * proof
    let (sum_pubkeys, sum_proofs) = public_keys.iter().enumerate().fold(
        (G1Affine::zero(), G2Affine::zero()),
        |(acc_pubkey, acc_proof), (index, (pubkey, proof))| {
            (
                (acc_pubkey + pubkey).into_affine(),
                (acc_proof
                    + proof.mul(Fr::from(new_key_index as u64 + 1) / (Fr::from(index as u64 + 1))))
                .into_affine(),
            )
        },
    );

    let new_key = (pubkey - sum_pubkeys).into_affine();
    let new_proof = (proof - sum_proofs).into_affine();
    let aggregate_signature = sign;

    /* End of solution */
```