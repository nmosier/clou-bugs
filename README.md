# Crypto-Library Bugs Detected by Clou

In this repository, we present Spectre v1 and v4 bugs we have discovered using Clou, a static analysis tool.
Each of these bugs have the potential to leak arbitrary memory in the victim program.

## Spectre v1
See [paper](https://spectreattack.com).

## Spectre v4

We find 3 variants of Spectre v4 bugs.
Variant A and B are both severe (more exploitable).
Variant C is more common and less exploitable, but still has the possibility to leak secrets at an attacker-controlled memory location. 

### Variant A: Classic Spectre v4
```
int *ptr = other_ptr; // bypassed store
int val = array[*ptr]; // Spectre v4 gadget
```
The load of `ptr` from the stack on line 2 may read a stale value due to Speculative Store Bypass ([CVE-2018-3639](https://cve.org/CVERecord?id=CVE-2018-3639)).
If this stale value is attacker-controlled, then the pointer dereference `*ptr` reads an arbitrary secret from memory, which is then used to index into array `array[]`, leaking the secret to the cache.

### Variant B: Spectre v4 with secret intermediate result
```
int *ptr = other_ptr; // bypassed store
int idx = *ptr; // secret intermediate result
int val = array[idx]; // leaks secret to cache
```
Like in Variant A, the load of `ptr` from the stack on line 2 may read a stale value due to Speculative Store Bypass ([CVE-2018-3639](https://cve.org/CVERecord?id=CVE-2018-3639)).
This time, the secret intermediate value is stored back onto the stack.
Later on, it is read back from memory and the secret is used to index into an array, leaking the secret into the cache.

### Variant C: Spectre v4 with Out of Bounds (OOB) Write
```
int *ptr = ...;
int idx = 0; // bypassed store
out[idx] = in[idx]; // OOB read of secret and OOB overwrite of pointer in memory
*ptr = 0; // access of overwritten pointer leaks secret into cachce
```
The load of `idx` from the stack on line 3 may read a stale value due to Speculative Store Bypass ([CVE-2018-3639](https://cve.org/CVERecord?id=CVE-2018-3639)).
If `idx` is attacker-controlled, this results in an OOB read from array `in`, which reads an attacker-controlled secret.
The attacker-controlled secret is then written outside of array `out`, potentially overwriting a pointer in memory, in this case `ptr`.
When that pointer `ptr` is subsequently dereferenced, the secret leaks to the cache.

This variant is less exploitable since it requires more restrictions to work. The attacker must choose an index that meets two criteria, rather than one:
1. `&in[idx]` points to a secret; and
2. `&out[idx]` points to a pointer in memory that will be subsequently accessed.
Variants A and B only require criterion (1). 
