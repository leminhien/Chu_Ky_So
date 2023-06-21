package digittal.signature.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;

public class AlgorithmRSA {

    private BigInteger n, d, e; 
    
    public AlgorithmRSA(BigInteger newn, BigInteger newe) {
        n = newn;
        e = newe;
    }
    
    public AlgorithmRSA() {

    }
    public BigInteger getN() {
        return n;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    public BigInteger getD() {
        return d;
    }

    public void setD(BigInteger d) {
        this.d = d;
    }

    public BigInteger getE() {
        return e;
    }

    public void setE(BigInteger e) {
        this.e = e;
    }

    

    public void KeyRSA(int bits) {
        SecureRandom r = new SecureRandom(); 
        BigInteger p = new BigInteger(bits / 2, 100, r);  
        BigInteger q = new BigInteger(bits / 2, 100, r);
        n = p.multiply(q); 
        BigInteger phiN = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        boolean found = false;
        do {
            e = new BigInteger(bits / 2, 100, r);
           
            if (phiN.gcd(e).equals(BigInteger.ONE) && e.compareTo(phiN) < 0) {
                found = true; 
            }
        } while (!found);
        d = e.modInverse(phiN); 
    }

    public synchronized BigInteger encrypt(BigInteger message) { //Mã hóa
        return message.modPow(d, n); 
    }


    public synchronized BigInteger decrypt(BigInteger message) { //Giải mã
        return message.modPow(e, n); 
    }
}
