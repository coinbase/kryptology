# Vulnerabilities in GG20

Recently, a number of attacks were announced against The paper _One Round Threshold ECDSA with Identifiable Abort_ by Rosario Gennaro and Steven Goldfeder [[GG20]](https://eprint.iacr.org/2020/540). These include:
 - Dmytro Tymokhanov and Omer Shlomovits. _Alpha-Rays: Key Extraction Attacks on Threshold ECDSA Implementations_ [[TS21]](https://eprint.iacr.org/2021/1621).
 - Nikolaos Makriyannis and Udi Peled. _A Note on the Security of GG18_ [[MP21]](https://info.fireblocks.com/hubfs/A_Note_on_the_Security_of_GG.pdf).

We have already incorporated and implemented a number of "fixes" to these attacks, described in the Dec. 17, 2021 version of [GG20]. On the other hand, the authors of that paper appear to have declared it "obsolete". In light of this declaration, we cannot attest, given the information we currently have, that the protocol implemented here is secure. We advise caution regarding its use.